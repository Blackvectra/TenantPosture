[
  {
    "ControlId": "AAD-1.1",
    "Category": "Identity",
    "Title": "Block legacy authentication protocols",
    "Severity": "Critical",
    "Description": "Legacy authentication protocols (POP, IMAP, basic auth) bypass modern conditional access and MFA. They must be blocked tenant-wide.",
    "BusinessRisk": "Legacy auth is the #1 vector for password spray and credential stuffing attacks. Microsoft data shows 99%+ of compromised accounts used legacy authentication.",
    "Remediation": "Create a Conditional Access policy: All users, All cloud apps, Client apps = Other clients, Grant = Block. Roll out in report-only first.",
    "RemediationLink": "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/PoliciesView",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "IA-2(1)",
        "IA-2(2)"
      ],
      "CIS-v8": [
        "6.3",
        "6.5"
      ],
      "CIS-M365-v6": [
        "5.2.2.4"
      ],
      "HIPAA": [
        "164.312(d)"
      ],
      "HIPAA-NPRM": [
        "164.312(d)"
      ],
      "ISO-27001": [
        "A.5.17",
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-01",
        "PR.AA-03"
      ],
      "SOC-2": [
        "CC6.1"
      ],
      "CISA-SCuBA": [
        "MS.AAD.1.1"
      ]
    }
  },
  {
    "ControlId": "AAD-1.2",
    "Category": "Identity",
    "Title": "Phishing-resistant MFA enforced for privileged roles",
    "Severity": "Critical",
    "Description": "Privileged accounts (Global Admin, Privileged Role Admin, etc.) must use phishing-resistant MFA methods (FIDO2 keys, Windows Hello for Business, certificate-based auth). SMS and voice are insufficient.",
    "BusinessRisk": "Privileged account compromise is the highest-impact incident type. Phishing-resistant MFA defeats AiTM (Adversary-in-the-Middle) attacks like Evilginx.",
    "Remediation": "Step 1 \u2014 Open Conditional Access: Entra admin center (entra.microsoft.com) > Protection > Conditional Access > Policies > New policy. Step 2 \u2014 Name the policy: 'Require phishing-resistant MFA for admin roles'. Step 3 \u2014 Users: Select users and groups > Directory roles > Select all privileged roles: Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator, Teams Administrator, Compliance Administrator, User Administrator, Application Administrator, Hybrid Identity Administrator, Billing Administrator. Step 4 \u2014 Target resources: All cloud apps. Step 5 \u2014 Grant: Select Grant access > Require authentication strength > Phishing-resistant MFA (covers FIDO2, Windows Hello for Business, and certificate-based auth). Step 6 \u2014 Enable policy: Set to Report-only first. Monitor sign-in logs for 1 week to confirm admin accounts have compliant auth methods registered. Then switch to On. Prerequisites: Admins must have FIDO2 keys, Windows Hello for Business, or certificates enrolled before enforcement. Use Temporary Access Pass (TAP) to onboard if needed.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(1)",
        "IA-2(2)",
        "IA-2(6)",
        "IA-2(8)"
      ],
      "CIS-v8": [
        "6.5"
      ],
      "CIS-M365-v6": [
        "5.2.3.4"
      ],
      "HIPAA": [
        "164.312(d)"
      ],
      "HIPAA-NPRM": [
        "164.312(d)"
      ],
      "ISO-27001": [
        "A.5.15",
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "SOC-2": [
        "CC6.1",
        "CC6.6"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.7"
      ]
    }
  },
  {
    "ControlId": "AAD-1.3",
    "Category": "Identity",
    "Title": "Privileged Identity Management used for admin roles",
    "Severity": "High",
    "Description": "Administrator roles should be assigned as Eligible (not Active) via PIM, requiring just-in-time activation with approval and time-bounded duration.",
    "BusinessRisk": "Permanent admin access means a compromised admin account immediately has maximum privileges. PIM limits the exposure window to only when privileges are actively needed.",
    "Remediation": "Migrate Active admin role assignments to Eligible via Entra PIM. Configure activation requirements (MFA, justification, approval). Requires Entra ID P2 license.",
    "RemediationLink": "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart",
    "EffortLevel": "Strategic (planning required)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-2(7)",
        "AC-6(2)",
        "AC-6(5)"
      ],
      "CIS-v8": [
        "5.4",
        "6.8"
      ],
      "CIS-M365-v6": [
        "5.3.1"
      ],
      "HIPAA": [
        "164.308(a)(3)(ii)(A)"
      ],
      "HIPAA-NPRM": [
        "164.308(a)(3)(ii)(A)"
      ],
      "ISO-27001": [
        "A.8.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "SOC-2": [
        "CC6.3"
      ],
      "CISA-SCuBA": [
        "MS.AAD.7.6",
        "MS.AAD.7.7"
      ]
    }
  },
  {
    "ControlId": "AAD-2.1",
    "Category": "Identity",
    "Title": "MFA registered for all enabled user accounts",
    "Severity": "High",
    "Description": "All enabled member accounts must have MFA registered before CA enforcement. Unregistered users will be locked out when MFA CA policies are enabled.",
    "BusinessRisk": "Accounts without MFA registered cannot be protected by MFA Conditional Access policies. These accounts remain vulnerable to password spray regardless of tenant CA configuration.",
    "Remediation": "Step 1 \u2014 Enable Registration Campaign: Entra admin center > Protection > Authentication methods > Registration campaign > Enable. Set nudge to 'Microsoft managed' or configure a specific number of days to postpone. Step 2 \u2014 Check which users are unregistered: Entra admin center > Identity > Users > All users > Authentication methods activity. Filter by 'Not registered for MFA'. Step 3 \u2014 Use Temporary Access Pass for bulk onboarding: For each unregistered user, issue a TAP (Entra admin center > Users > [user] > Authentication methods > Add authentication method > Temporary access pass). User enters TAP once and registers their preferred MFA method \u2014 no helpdesk calls required. Step 4 \u2014 Do not enforce CA MFA policy (AAD-3.1) until registration is above 95%. Enforcing at 80% will lock out the unregistered 20%. Step 5 \u2014 Track progress weekly via the Authentication methods activity report.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(1)",
        "IA-2(2)"
      ],
      "CIS-v8": [
        "6.3",
        "6.5"
      ],
      "CIS-M365-v6": [
        "5.2.1"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.1"
      ]
    }
  },
  {
    "ControlId": "AAD-2.2",
    "Category": "Identity",
    "Title": "MFA enforced via Conditional Access (not per-user MFA or Security Defaults)",
    "Severity": "High",
    "Description": "MFA enforcement must be implemented through Conditional Access policies, not per-user MFA legacy configuration or Security Defaults. Security Defaults is mutually exclusive with CA and cannot accommodate break-glass exceptions.",
    "BusinessRisk": "Security Defaults blocks all Conditional Access. Per-user MFA is unmanageable at scale and does not support named location exclusions, risk-based stepping, or emergency bypass.",
    "Remediation": "Disable Security Defaults. Disable per-user MFA for all accounts. Implement MFA via CA policy targeting All users, All cloud apps.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(1)",
        "IA-2(2)"
      ],
      "CIS-M365-v6": [
        "5.2.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.2"
      ]
    }
  },
  {
    "ControlId": "AAD-2.3",
    "Category": "Identity",
    "Title": "Authenticator app number matching enabled",
    "Severity": "High",
    "Description": "Microsoft Authenticator number matching must be enabled to prevent MFA fatigue attacks. Microsoft enforces this as a platform default since May 2023. Verify it has not been explicitly disabled.",
    "BusinessRisk": "MFA fatigue (T1621) is an active attack technique. Attackers spam MFA push notifications until the user approves one. Number matching defeats this by requiring the user to enter a code displayed during sign-in.",
    "Remediation": "Note: Microsoft enforced number matching as a platform default in May 2023. If your tenant shows this as not configured, it is already enforced automatically \u2014 you cannot disable it on current tenants. To explicitly confirm and enable additional context: Step 1 \u2014 Entra admin center > Protection > Authentication methods > Microsoft Authenticator. Step 2 \u2014 Click Configure next to All users (or your target group). Step 3 \u2014 Under Number matching: set to Enabled. Step 4 \u2014 Under Additional context (shows app name and location in push notification): set to Enabled. Step 5 \u2014 Save. Takes effect on next push notification \u2014 zero downtime, no user action required. Impact: Eliminates MFA fatigue attacks. Users see a 2-digit code in the sign-in page and must match it in the Authenticator app \u2014 a passive approval is impossible.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(8)"
      ],
      "CIS-M365-v6": [
        "5.2.1.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.6"
      ]
    }
  },
  {
    "ControlId": "AAD-2.4",
    "Category": "Identity",
    "Title": "Security Defaults disabled in favor of Conditional Access",
    "Severity": "Medium",
    "Description": "Security Defaults must be disabled in any tenant using Conditional Access policies. The two are mutually exclusive. Active Security Defaults blocks all CA enforcement.",
    "BusinessRisk": "A tenant with Security Defaults enabled cannot enforce CA policies. Break-glass exclusions, named locations, and risk-based enforcement are all blocked.",
    "Remediation": "Entra ID > Properties > Manage Security Defaults > Disabled. Ensure equivalent CA policies are enforced before disabling.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "IA-2(2)"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.2"
      ]
    }
  },
  {
    "ControlId": "AAD-3.1",
    "Category": "Identity",
    "Title": "Conditional Access: MFA required for all users on all cloud apps",
    "Severity": "Critical",
    "Description": "A Conditional Access policy must be in enabled (enforced) state requiring MFA for all users on all cloud apps. Report-only does not protect the tenant.",
    "BusinessRisk": "Without enforced MFA, compromised credentials provide immediate account access. Password spray and credential stuffing attacks succeed against any account without MFA enforcement.",
    "Remediation": "Step 1 \u2014 Prerequisite: Complete AAD-2.1 first. Do not enforce this policy until MFA registration exceeds 95%. Step 2 \u2014 Create policy: Entra admin center > Protection > Conditional Access > New policy. Name: 'Require MFA for all users'. Step 3 \u2014 Users: All users. Exclude: your break-glass account(s) by username \u2014 never exclude by group. Step 4 \u2014 Target resources: All cloud apps. Step 5 \u2014 Grant: Require multifactor authentication. Step 6 \u2014 Enable: Set to Report-only first. Review sign-in logs at Entra > Monitoring > Sign-in logs for 48 hours. Confirm no unexpected failures. Step 7 \u2014 Switch to On. Communicate to users before enforcement \u2014 they will be prompted on next sign-in if not already registered. Note: Accounts enrolled with per-user MFA instead of CA should be migrated \u2014 per-user MFA and CA MFA can conflict.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(1)",
        "IA-2(2)"
      ],
      "CIS-v8": [
        "6.3",
        "6.5"
      ],
      "CIS-M365-v6": [
        "5.2.2.1"
      ],
      "HIPAA": [
        "164.312(d)"
      ],
      "ISO-27001": [
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "SOC-2": [
        "CC6.1"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.2"
      ]
    }
  },
  {
    "ControlId": "AAD-3.2",
    "Category": "Identity",
    "Title": "Conditional Access: Legacy authentication blocked",
    "Severity": "Critical",
    "Description": "A dedicated CA policy must block legacy authentication client apps (client app types: Other, Exchange ActiveSync). Blocking at transport config alone is insufficient.",
    "BusinessRisk": "Legacy auth bypasses MFA and CA entirely. Microsoft data: 99%+ of compromised M365 accounts used legacy auth. One enabled legacy auth path voids all MFA investment.",
    "Remediation": "CA policy: All users, All cloud apps, Client apps = Other clients + Exchange ActiveSync, Grant = Block. Verify SMTP AUTH is also disabled at transport layer (EXO-1.2).",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "IA-2(1)",
        "AC-17"
      ],
      "CIS-v8": [
        "6.3"
      ],
      "CIS-M365-v6": [
        "5.2.2.4"
      ],
      "ISO-27001": [
        "A.5.17",
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.1.1"
      ]
    }
  },
  {
    "ControlId": "AAD-3.3",
    "Category": "Identity",
    "Title": "Conditional Access: MFA required for Azure management",
    "Severity": "High",
    "Description": "A CA policy must enforce MFA specifically for Azure management access (Azure portal, Azure CLI, Azure PowerShell). Admin-level cloud access must have independent MFA enforcement.",
    "BusinessRisk": "Azure management access allows subscription-level resource control, tenant configuration, and data exfiltration. A compromised admin credential without MFA can destroy an entire cloud environment.",
    "Remediation": "Step 1 \u2014 Entra admin center > Protection > Conditional Access > New policy. Name: 'Require MFA for Azure management'. Step 2 \u2014 Users: All users (or scope to your admin accounts). Exclude break-glass. Step 3 \u2014 Target resources: Select apps > Search for 'Microsoft Azure Management' (App ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013). Select it. This covers the Azure portal, Azure CLI, Azure PowerShell, and Azure mobile app. Step 4 \u2014 Grant: Require multifactor authentication. Step 5 \u2014 Enable: On (this is low risk to enable directly \u2014 if an admin cannot complete MFA for Azure, they should not be performing Azure admin actions). Alternative: Add Microsoft Azure Management to your existing all-users MFA policy (AAD-3.1) target resources instead of creating a separate policy.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(1)",
        "AC-6(5)"
      ],
      "CIS-M365-v6": [
        "5.2.2.3"
      ],
      "NIST-CSF-2": [
        "PR.AA-03",
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.4"
      ]
    }
  },
  {
    "ControlId": "AAD-3.4",
    "Category": "Identity",
    "Title": "No Conditional Access policies remaining in report-only mode",
    "Severity": "Medium",
    "Description": "CA policies in report-only mode provide no enforcement. Each report-only policy must either be enforced or documented with explicit rationale for deferred enforcement.",
    "BusinessRisk": "Report-only policies are commonly left behind after initial deployment. They create a false sense of coverage while providing zero protection.",
    "Remediation": "Review all report-only policies in Entra ID > Conditional Access. Enforce policies with sufficient registration coverage or document acceptance. Remove stale report-only policies.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "CM-7"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.3.2"
      ]
    }
  },
  {
    "ControlId": "AAD-3.5",
    "Category": "Identity",
    "Title": "Conditional Access: Sign-in risk policy configured (Entra ID P2)",
    "Severity": "High",
    "Description": "A CA policy must respond to sign-in risk signals from Entra ID Protection. Medium+ risk should trigger MFA step-up; High risk should block or require MFA + compliant device.",
    "BusinessRisk": "Without risk-based CA, anomalous sign-ins (impossible travel, malicious IP, atypical behavior) proceed without interruption. Entra ID Protection detects these signals but cannot act without a CA policy consuming them.",
    "Remediation": "Entra ID P2 required. CA policy: All users, All cloud apps, Sign-in risk = Medium + High, Grant = Require MFA (or block for High). Also configure user risk policy (AAD-3.6).",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "SI-4",
        "AU-6"
      ],
      "CIS-M365-v6": [
        "5.2.2.2"
      ],
      "ISO-27001": [
        "A.8.16"
      ],
      "NIST-CSF-2": [
        "DE.CM-01",
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.2.1"
      ]
    }
  },
  {
    "ControlId": "AAD-3.6",
    "Category": "Identity",
    "Title": "Conditional Access: User risk policy configured (Entra ID P2)",
    "Severity": "High",
    "Description": "A CA policy must respond to user risk signals (leaked credentials, suspicious activity patterns). High user risk should require password change or block sign-in pending investigation.",
    "BusinessRisk": "User risk reflects cumulative identity compromise signals. An account flagged high-risk represents a likely credential compromise. Without a user risk policy, these accounts continue operating without interruption.",
    "Remediation": "Entra ID P2 required. CA policy: All users, All cloud apps, User risk = High, Grant = Block (or require password change + MFA).",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "IR-4",
        "SI-4"
      ],
      "CIS-M365-v6": [
        "5.2.2.2"
      ],
      "NIST-CSF-2": [
        "DE.CM-01",
        "RS.AN-03"
      ],
      "CISA-SCuBA": [
        "MS.AAD.2.3"
      ]
    }
  },
  {
    "ControlId": "AAD-4.1",
    "Category": "Identity",
    "Title": "Global Administrator count between 2 and 5",
    "Severity": "High",
    "Description": "The number of permanent Global Administrator role holders must be between 2 (for redundancy) and 5 (to limit blast radius). PIM eligible assignments are preferred and do not count toward this limit.",
    "BusinessRisk": "Too few GAs create recovery risk. Too many expand the attack surface. Every additional permanent GA is another account that can be compromised for full tenant takeover.",
    "Remediation": "Review Global Admin assignments. Reduce excess admins to scoped roles. Migrate remaining GAs to PIM eligible assignments where P2 is available.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-2",
        "AC-6(5)"
      ],
      "CIS-v8": [
        "5.4"
      ],
      "CIS-M365-v6": [
        "5.3.1"
      ],
      "ISO-27001": [
        "A.8.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.AAD.7.1"
      ]
    }
  },
  {
    "ControlId": "AAD-4.2",
    "Category": "Identity",
    "Title": "No on-premises synced accounts hold Entra ID admin roles",
    "Severity": "Critical",
    "Description": "Accounts synchronized from on-premises Active Directory via Entra Connect must not hold any Entra ID directory roles. An on-prem AD compromise directly results in tenant admin compromise.",
    "BusinessRisk": "An attacker who compromises on-prem AD can immediately elevate to Entra ID Global Admin if synced accounts hold admin roles. This is a complete hybrid identity kill chain (T1078.002).",
    "Remediation": "Remove all Entra ID role assignments from on-premises synced accounts. Create dedicated cloud-only admin accounts (no sync).",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-6(5)",
        "IA-2(6)",
        "SC-50"
      ],
      "CIS-v8": [
        "5.4"
      ],
      "CIS-M365-v6": [
        "5.3.1"
      ],
      "ISO-27001": [
        "A.8.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.AAD.7.4"
      ]
    }
  },
  {
    "ControlId": "AAD-4.3",
    "Category": "Identity",
    "Title": "Global Administrator accounts are dedicated (no assigned licenses)",
    "Severity": "High",
    "Description": "Global Administrator accounts must be dedicated admin-only accounts with no M365 licenses assigned. Licensed GA accounts are daily-use accounts with admin privileges, maximizing credential compromise impact.",
    "BusinessRisk": "Daily-use GA accounts are exposed to phishing, malware, and browser-based attacks during normal work. A compromised daily-use account with GA access is an immediate full-tenant compromise.",
    "Remediation": "Step 1 \u2014 Create dedicated admin accounts: Entra admin center > Users > New user. Naming convention: admin-firstname@domain.com or firstname-adm@domain.com. No license assigned. No mailbox. Used only for admin tasks. Step 2 \u2014 Assign GA role to the new account: Entra admin center > Roles and administrators > Global Administrator > Add assignments. Add the new admin account. Step 3 \u2014 Remove GA from daily-use licensed accounts: Entra admin center > Roles and administrators > Global Administrator > Remove the daily-use accounts. Step 4 \u2014 Assign daily-use accounts appropriate scoped roles only if needed (e.g. Security Reader, Helpdesk Administrator). Step 5 \u2014 Ensure the dedicated admin account is covered by your phishing-resistant MFA CA policy (AAD-1.2). Note: Daily admin workflow \u2014 log in to Microsoft 365 with daily account for email and productivity. Open a separate browser or InPrivate window and sign in with the admin account only when performing admin tasks.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-6(2)",
        "AC-6(5)"
      ],
      "CIS-v8": [
        "5.4"
      ],
      "CIS-M365-v6": [
        "5.3.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.AAD.7.3"
      ]
    }
  },
  {
    "ControlId": "AAD-4.4",
    "Category": "Identity",
    "Title": "PIM used for Global Administrator role (JIT access model)",
    "Severity": "High",
    "Description": "Global Administrator access must be granted via PIM eligible assignments with just-in-time activation. Permanent GA role holders should be limited to break-glass accounts only.",
    "BusinessRisk": "Permanent Global Admin access means a compromised account has full tenant privileges immediately. PIM limits the exposure window to active activation periods (typically 1-8 hours) with MFA verification and audit trail.",
    "Remediation": "Step 1 \u2014 Verify PIM is licensed: Entra ID P2 or Microsoft 365 E5 required. Entra admin center > Identity governance > Privileged Identity Management. Step 2 \u2014 Configure GA as eligible in PIM: PIM > Entra roles > Global Administrator > Assignments > Add assignments > Assignment type = Eligible. Select the admin accounts to make eligible. Set duration to permanent eligible (no expiry on eligibility). Step 3 \u2014 Configure activation settings: PIM > Entra roles > Global Administrator > Settings > Edit. Require MFA on activation: Yes. Require justification: Yes. Max activation duration: 8 hours. Require approval: Optional \u2014 recommended for production tenants. Step 4 \u2014 Remove permanent active assignments: PIM > Entra roles > Global Administrator > Assignments > Active tab. Remove all active assignments except your break-glass account. Step 5 \u2014 Activate when needed: Admin goes to PIM > My roles > Eligible > Global Administrator > Activate. Completes MFA, enters justification, receives activation for up to 8 hours. Step 6 \u2014 Verify sign-in logs confirm PIM activations are being used within 30 days.",
    "RemediationLink": "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-2(7)",
        "AC-6(2)",
        "AC-6(5)"
      ],
      "CIS-v8": [
        "5.4",
        "6.8"
      ],
      "CIS-M365-v6": [
        "5.3.1"
      ],
      "ISO-27001": [
        "A.8.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.AAD.7.6",
        "MS.AAD.7.7"
      ]
    }
  },
  {
    "ControlId": "AAD-4.5",
    "Category": "Identity",
    "Title": "Break-glass Global Administrator account exists",
    "Severity": "High",
    "Description": "At least one dedicated break-glass (emergency access) Global Administrator account must exist: cloud-only, unlicensed, excluded from MFA CA via named location, credentials stored offline.",
    "BusinessRisk": "Without a break-glass account, a failed MFA provider, misconfigured CA policy, or identity system outage can lock all administrators out of the tenant permanently. Recovery requires Microsoft Support with multi-day turnaround.",
    "Remediation": "Step 1 \u2014 Identify or create the break-glass account: Should be cloud-only (not synced from on-premises), unlicensed, and not tied to any individual person. Naming: breakglass@domain.com or emergency-admin@domain.com. Step 2 \u2014 Assign Global Administrator permanently (not via PIM \u2014 break-glass must work if PIM is unavailable). Step 3 \u2014 Exclude from all MFA CA policies: Create a named location for the break-glass account, or exclude by username. This is intentional \u2014 the account must work even if the MFA infrastructure fails. Step 4 \u2014 Secure the credentials: Print the username and password. Store in a sealed envelope in a physical safe or safety deposit box. Never save digitally or in a password manager. Step 5 \u2014 Configure a sign-in alert: Entra admin center > Monitoring > Workbooks > Sign-ins \u2014 or create an Azure Monitor alert on sign-in events for this account. Any sign-in from this account should page your on-call team immediately. Step 6 \u2014 Test quarterly: Sign in with the break-glass account from a known IP. Confirm the alert fires. Rotate the password after each test and update the sealed envelope.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-2(7)",
        "CP-6",
        "IR-4"
      ],
      "CIS-M365-v6": [
        "5.3.1"
      ],
      "ISO-27001": [
        "A.17.1.1"
      ],
      "NIST-CSF-2": [
        "PR.AA-05",
        "RC.RP-01"
      ],
      "CISA-SCuBA": [
        "MS.AAD.7.2"
      ]
    }
  },
  {
    "ControlId": "EXO-1.1",
    "Category": "Email Security",
    "Title": "Mailbox audit enabled tenant-wide",
    "Severity": "High",
    "Description": "Mailbox audit logging must be enabled and no mailbox should have AuditBypassEnabled=True. Bypass disables forensics for that user.",
    "BusinessRisk": "Without mailbox auditing, BEC investigations are impossible. AuditBypassEnabled accounts leave zero forensic trail of mailbox actions.",
    "Remediation": "Set-OrganizationConfig -AuditDisabled $false. For each bypassed mailbox: Set-MailboxAuditBypassAssociation -Identity <mbx> -AuditBypassEnabled $false",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AU-2",
        "AU-9",
        "AU-12"
      ],
      "CIS-v8": [
        "8.2",
        "8.5"
      ],
      "CIS-M365-v6": [
        "6.1.3"
      ],
      "HIPAA": [
        "164.312(b)"
      ],
      "HIPAA-NPRM": [
        "164.312(b)"
      ],
      "ISO-27001": [
        "A.8.15"
      ],
      "NIST-CSF-2": [
        "DE.CM-09"
      ],
      "SOC-2": [
        "CC7.2"
      ]
    }
  },
  {
    "ControlId": "EXO-1.2",
    "Category": "Email Security",
    "Title": "SMTP client authentication disabled tenant-wide",
    "Severity": "Critical",
    "Description": "SMTP AUTH (basic authentication for sending mail) must be disabled at the tenant level and on individual mailboxes. It bypasses MFA and Conditional Access.",
    "BusinessRisk": "SMTP AUTH is exploited for outbound spam and impersonation after credential compromise. Most environments don't need it.",
    "Remediation": "Set-TransportConfig -SmtpClientAuthenticationDisabled $true. Verify per-mailbox: Get-CASMailbox | Where SmtpClientAuthenticationDisabled -ne $true",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "AC-17"
      ],
      "CIS-v8": [
        "6.3"
      ],
      "CIS-M365-v6": [
        "6.4.1"
      ],
      "HIPAA": [
        "164.312(e)"
      ],
      "ISO-27001": [
        "A.5.17",
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.EXO.4.1"
      ]
    }
  },
  {
    "ControlId": "EXO-2.1",
    "Category": "Email Security",
    "Title": "DMARC enforcement policy",
    "Severity": "High",
    "Description": "All sending domains should have a DMARC record published at p=reject (or at minimum p=quarantine with monitoring). p=none provides no protection.",
    "BusinessRisk": "Without DMARC enforcement, attackers can spoof your domain in phishing emails to your customers and partners. BEC and brand-impersonation attacks rely on weak DMARC.",
    "Remediation": "Publish DMARC TXT record: v=DMARC1; p=reject; rua=mailto:rua@dmarcian.com; pct=100; adkim=s; aspf=s. Stage via p=none -> p=quarantine -> p=reject.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-8",
        "SC-8"
      ],
      "CIS-v8": [
        "9.5"
      ],
      "CIS-M365-v6": [
        "2.1.8"
      ],
      "ISO-27001": [
        "A.8.20"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ],
      "CISA-SCuBA": [
        "MS.EXO.2.2"
      ],
      "CISA-BOD": [
        "BOD 18-01"
      ]
    }
  },
  {
    "ControlId": "EXO-2.2",
    "Category": "Email Security",
    "Title": "POP3 disabled for all mailboxes",
    "Severity": "High",
    "Description": "POP3 must be disabled for all mailboxes. POP3 uses basic authentication, bypasses MFA and Conditional Access, and provides legacy access to mailbox content.",
    "BusinessRisk": "POP3 is a legacy protocol that bypasses modern authentication controls. Enabled POP3 means any mailbox is accessible via password-only authentication regardless of MFA enforcement. T1114 (Email Collection).",
    "Remediation": "Set-CASMailboxPlan -PopEnabled $false. For existing mailboxes: Get-CASMailbox | Set-CASMailbox -PopEnabled $false. Verify: Get-CASMailbox | Where PopEnabled | Measure-Object",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "CM-7"
      ],
      "CIS-v8": [
        "4.8"
      ],
      "CIS-M365-v6": [
        "6.5.1"
      ],
      "ISO-27001": [
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.EXO.10.1"
      ]
    }
  },
  {
    "ControlId": "EXO-2.3",
    "Category": "Email Security",
    "Title": "IMAP disabled for all mailboxes",
    "Severity": "High",
    "Description": "IMAP must be disabled for all mailboxes. IMAP uses basic authentication, bypasses MFA and Conditional Access, and exposes mailbox contents to legacy protocol attacks.",
    "BusinessRisk": "IMAP bypasses modern authentication controls identically to POP3. Password spray attacks against IMAP are trivial and commonly used to bypass MFA-enforced tenants. T1114 (Email Collection).",
    "Remediation": "Set-CASMailboxPlan -ImapEnabled $false. For existing mailboxes: Get-CASMailbox | Set-CASMailbox -ImapEnabled $false. Verify count with: Get-CASMailbox | Where ImapEnabled | Measure-Object",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "CM-7"
      ],
      "CIS-v8": [
        "4.8"
      ],
      "CIS-M365-v6": [
        "6.5.2"
      ],
      "ISO-27001": [
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.EXO.10.2"
      ]
    }
  },
  {
    "ControlId": "EXO-2.4",
    "Category": "Email Security",
    "Title": "Customer Lockbox enabled",
    "Severity": "Medium",
    "Description": "Customer Lockbox requires explicit customer approval before Microsoft support engineers can access tenant data during a support request.",
    "BusinessRisk": "Without Customer Lockbox, Microsoft support can access mailbox data during support incidents without explicit customer consent. For regulated industries (HIPAA, government) this is a compliance gap.",
    "Remediation": "Microsoft 365 admin center > Org settings > Security & privacy > Customer Lockbox > Enable. Requires Microsoft 365 E3/E5 or equivalent licensing.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-2",
        "AC-3"
      ],
      "CIS-M365-v6": [
        "1.1.3"
      ],
      "HIPAA": [
        "164.312(a)(1)"
      ],
      "ISO-27001": [
        "A.8.3"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "SOC-2": [
        "CC6.3"
      ],
      "CISA-SCuBA": [
        "MS.EXO.15.1"
      ]
    }
  },
  {
    "ControlId": "EXO-2.5",
    "Category": "Email Security",
    "Title": "Shared mailbox sign-in disabled",
    "Severity": "High",
    "Description": "Shared mailboxes must have direct sign-in (AccountEnabled) disabled. Shared mailboxes should only be accessed via delegation, not direct authentication.",
    "BusinessRisk": "Shared mailboxes with sign-in enabled are service accounts that can be authenticated directly. They are often excluded from MFA policies and represent a silent bypass for credential-based attacks. T1078 (Valid Accounts).",
    "Remediation": "For each shared mailbox: Set-AzureADUser -ObjectId [UPN] -AccountEnabled $false. Or via M365 admin center: Users > [shared mailbox] > Block sign-in.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-2",
        "AC-6"
      ],
      "CIS-v8": [
        "5.3"
      ],
      "CIS-M365-v6": [
        "1.2.2"
      ],
      "ISO-27001": [
        "A.8.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.EXO.9.1"
      ]
    }
  },
  {
    "ControlId": "EXO-3.1",
    "Category": "Email Security",
    "Title": "Modern authentication enabled for Exchange Online",
    "Severity": "High",
    "Description": "OAuth2-based modern authentication (OAuth2ClientProfileEnabled) must be enabled for Exchange Online. This is the prerequisite for MFA and Conditional Access to apply to Outlook clients.",
    "BusinessRisk": "Without modern authentication, Outlook desktop clients and mobile apps use basic authentication regardless of MFA policies. MFA cannot be enforced on mail clients connecting via basic auth.",
    "Remediation": "Set-OrganizationConfig -OAuth2ClientProfileEnabled $true. Should already be enabled in most tenants provisioned after 2017, but verify explicitly.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2",
        "IA-2(1)"
      ],
      "CIS-M365-v6": [
        "6.5.3"
      ],
      "ISO-27001": [
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.EXO.3.1"
      ]
    }
  },
  {
    "ControlId": "DEF-1.1",
    "Category": "Defender",
    "Title": "Anti-phishing policy with impersonation protection",
    "Severity": "High",
    "Description": "Default and custom anti-phishing policies should be configured with impersonation protection for users, domains, and trusted senders.",
    "BusinessRisk": "Phishing is the #1 method attackers use to compromise organizations. Without impersonation protection, look-alike domain and user attacks succeed.",
    "Remediation": "Step 1 \u2014 Verify the preset policy is active: Microsoft Defender portal (security.microsoft.com) > Email & Collaboration > Policies & Rules > Threat policies > Preset security policies. Under Strict protection, click Manage protection settings and confirm the policy is assigned to All recipients or your specific domains. Step 2 \u2014 If using a custom policy instead: Threat policies > Anti-phishing > select your policy > Edit assigned users. Add your accepted domains or All recipients. Step 3 \u2014 Verify impersonation settings are on: Edit the policy > Impersonation tab > enable 'Enable users to protect' (add key executives) and 'Enable domains to protect' (add your domains). Step 4 \u2014 Set action: Under Actions, set 'If message is detected as an impersonated user/domain' to Quarantine or Move to Junk. Note: Preset policies auto-apply rules \u2014 if using Strict preset, ensure recipients are assigned in the preset policy page, not the individual policy.",
    "RemediationLink": "https://security.microsoft.com/antiphishing",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-3",
        "SI-4"
      ],
      "CIS-v8": [
        "9.6"
      ],
      "CIS-M365-v6": [
        "2.1.7"
      ],
      "HIPAA": [
        "164.308(a)(5)(ii)(B)"
      ],
      "HIPAA-NPRM": [
        "164.308(a)(5)(ii)(B)"
      ],
      "ISO-27001": [
        "A.8.7"
      ],
      "NIST-CSF-2": [
        "PR.PS-05",
        "DE.CM-01"
      ],
      "CISA-SCuBA": [
        "MS.DEFENDER.1.1"
      ]
    }
  },
  {
    "ControlId": "DEF-1.2",
    "Category": "Defender",
    "Title": "Safe Attachments policy with Block action",
    "Severity": "High",
    "Description": "Defender for Office 365 Safe Attachments must be enabled with action set to Block. Detonates attachments in a sandbox before delivery.",
    "BusinessRisk": "Ransomware is most commonly delivered via email attachments. Without Safe Attachments, one malicious file opened by one employee can encrypt the entire organization's data.",
    "Remediation": "Create Safe Attachments policy: Action = Block, applied to all users. Requires Defender for Office 365 Plan 1 or 2.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-3",
        "SI-8"
      ],
      "CIS-v8": [
        "9.6",
        "10.5"
      ],
      "CIS-M365-v6": [
        "2.1.4",
        "2.1.5"
      ],
      "HIPAA": [
        "164.308(a)(5)(ii)(B)"
      ],
      "ISO-27001": [
        "A.8.7"
      ],
      "NIST-CSF-2": [
        "PR.PS-05",
        "DE.CM-01"
      ],
      "SOC-2": [
        "CC6.8"
      ],
      "CISA-SCuBA": [
        "MS.DEFENDER.4.1"
      ]
    }
  },
  {
    "ControlId": "DEF-1.3",
    "Category": "Defender",
    "Title": "Safe Links policy enabled tenant-wide",
    "Severity": "High",
    "Description": "Defender for Office 365 Safe Links must be enabled for Email, Teams, and Office 365 apps. Re-evaluates URLs at click time to catch time-of-click attacks.",
    "BusinessRisk": "Attackers use URLs that appear safe when sent but redirect to malicious sites after delivery. Safe Links re-checks every link at click time.",
    "Remediation": "Step 1 \u2014 Open the Safe Links policy: Microsoft Defender portal (security.microsoft.com) > Email & Collaboration > Policies & Rules > Threat policies > Safe Links. Step 2 \u2014 Edit your active policy (e.g. 'Protect Safe Links'): Click the policy name > Edit. Step 3 \u2014 Under URL & click protection settings, find 'Let users click through to the original URL'. Uncheck this option. This is the AllowClickThrough=True gap \u2014 once unchecked, users cannot bypass Safe Links warnings. Step 4 \u2014 Also verify: 'On: Safe Links checks a list of known, malicious links when users click links in email' is enabled. 'Apply Safe Links to email messages sent within the organization' is enabled. Step 5 \u2014 Save and confirm the policy rule targets All recipients or your accepted domains. Impact: Users clicking a malicious link will see a block page and cannot proceed. No end-user training required \u2014 it is enforced automatically.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-3"
      ],
      "CIS-v8": [
        "9.7"
      ],
      "CIS-M365-v6": [
        "2.1.1"
      ],
      "HIPAA": [
        "164.308(a)(5)(ii)(B)"
      ],
      "ISO-27001": [
        "A.8.7"
      ],
      "NIST-CSF-2": [
        "PR.PS-05"
      ],
      "CISA-SCuBA": [
        "MS.DEFENDER.5.1"
      ]
    }
  },
  {
    "ControlId": "DNS-1.1",
    "Category": "Email Security",
    "Title": "SPF record published",
    "Severity": "Medium",
    "Description": "Sender Policy Framework (SPF) TXT record must be published for each sending domain, ending in -all (hard fail) or ~all (soft fail).",
    "BusinessRisk": "Without SPF, recipient mail servers cannot validate which IPs are authorized to send for your domain. Required for DMARC alignment.",
    "Remediation": "Publish SPF TXT record. Example: 'v=spf1 include:spf.protection.outlook.com -all'",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-8"
      ],
      "CIS-v8": [
        "9.5"
      ],
      "CIS-M365-v6": [
        "2.1.9"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ],
      "CISA-BOD": [
        "BOD 18-01"
      ]
    }
  },
  {
    "ControlId": "DNS-1.2",
    "Category": "Email Security",
    "Title": "DKIM signing enabled",
    "Severity": "Medium",
    "Description": "DKIM (DomainKeys Identified Mail) must be enabled in Exchange Online and CNAME records published for each sending domain.",
    "BusinessRisk": "Without DKIM, emails fail DMARC alignment unless SPF passes. DKIM provides domain-anchored cryptographic identity verification.",
    "Remediation": "In Defender Portal > Policies > DKIM, enable signing for each domain. Publish selector1._domainkey and selector2._domainkey CNAMEs at registrar.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-8"
      ],
      "CIS-v8": [
        "9.5"
      ],
      "CIS-M365-v6": [
        "2.1.10"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ],
      "CISA-BOD": [
        "BOD 18-01"
      ]
    }
  },
  {
    "ControlId": "DNS-2.1",
    "Category": "Email Security",
    "Title": "MTA-STS policy enforced",
    "Severity": "Medium",
    "Description": "MTA-STS (Mail Transfer Agent Strict Transport Security) must be published with mode=enforce. This forces sending mail servers to use TLS when delivering to your domain and prevents TLS downgrade attacks.",
    "BusinessRisk": "Without MTA-STS enforce mode, attackers can perform SMTP TLS downgrade attacks (STARTTLS stripping) to intercept email in transit. mode=testing provides monitoring only \u2014 zero enforcement.",
    "Remediation": "Publish _mta-sts.[domain] TXT record: 'v=STSv1; id=[timestamp]'. Host policy file at https://mta-sts.[domain]/.well-known/mta-sts.txt with: version: STSv1, mode: enforce, mx: [your-mx-host], max_age: 86400. Stage with mode: testing first.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SC-8",
        "SC-8(1)"
      ],
      "CIS-v8": [
        "3.10"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ],
      "CISA-BOD": [
        "BOD 18-01"
      ]
    }
  },
  {
    "ControlId": "DNS-2.2",
    "Category": "Email Security",
    "Title": "TLS-RPT configured for sending domains",
    "Severity": "Low",
    "Description": "TLS-RPT (SMTP TLS Reporting) sends aggregate reports of TLS connection failures to a specified email or HTTPS endpoint. Required for visibility into MTA-STS enforcement failures.",
    "BusinessRisk": "Without TLS-RPT, TLS connection failures and MTA-STS policy violations are invisible. Silent failures mean misconfigured enforcement goes undetected until mail is lost.",
    "Remediation": "Publish TXT record at _smtp._tls.[domain]: 'v=TLSRPTv1; rua=mailto:tls-rpt@[domain]'. Route reports to DMARCian, Postmaster Tools, or a monitored mailbox.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "SC-8",
        "AU-6"
      ],
      "NIST-CSF-2": [
        "PR.DS-02",
        "DE.CM-09"
      ]
    }
  },
  {
    "ControlId": "DNS-2.3",
    "Category": "Email Security",
    "Title": "DNSSEC enabled for sending domains",
    "Severity": "Low",
    "Description": "DNSSEC cryptographically signs DNS records, preventing DNS spoofing and cache poisoning attacks against SPF, DKIM, DMARC, and MTA-STS records.",
    "BusinessRisk": "Without DNSSEC, attackers can poison DNS caches to redirect SPF/DMARC/MTA-STS lookups to attacker-controlled records, bypassing email authentication entirely.",
    "Remediation": "Enable DNSSEC at your domain registrar. GoDaddy, Cloudflare, and most enterprise registrars support this. Requires DS record publication \u2014 coordinate with registrar.",
    "EffortLevel": "Strategic (planning required)",
    "Frameworks": {
      "NIST-800-53": [
        "SC-20",
        "SC-21"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ],
      "CISA-BOD": [
        "BOD 18-01"
      ]
    }
  },
  {
    "ControlId": "SPO-1.1",
    "Category": "SharePoint",
    "Title": "SharePoint tenant external sharing restricted",
    "Severity": "High",
    "Description": "The SharePoint tenant-level external sharing capability must be set to ExistingExternalUserSharingOnly or Disabled. Allowing sharing with new external users or anyone exposes organisational content beyond the controlled user base.",
    "BusinessRisk": "Unrestricted external sharing means any user can share any document with anyone outside the organisation, including anonymous access. A single misconfigured share can expose confidential files publicly.",
    "Remediation": "SharePoint admin center > Policies > Sharing > External sharing > Set SharePoint to 'Existing guests only' or 'Only people in your organization'.",
    "RemediationLink": "https://admin.microsoft.com/sharepoint",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-3",
        "AC-22"
      ],
      "CIS-v8": [
        "3.3"
      ],
      "ISO-27001": [
        "A.8.3"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.SPO.1.1"
      ]
    }
  },
  {
    "ControlId": "SPO-1.2",
    "Category": "SharePoint",
    "Title": "Default sharing link type set to internal or specific people",
    "Severity": "Medium",
    "Description": "The default sharing link type must not be 'Anyone' (anonymous). Default should be 'Only people in your organization' (internal) or 'Specific people' so users do not accidentally create anonymous links.",
    "BusinessRisk": "When the default link type is 'Anyone', users sharing content create anonymous links by default. A single accidental share creates a public URL accessible to anyone with the link.",
    "Remediation": "SharePoint admin center > Policies > Sharing > Default link type > Select 'Only people in your organization'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-22"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.SPO.1.2"
      ]
    }
  },
  {
    "ControlId": "SPO-1.3",
    "Category": "SharePoint",
    "Title": "Anyone link expiration enforced (30 days or less)",
    "Severity": "Medium",
    "Description": "If Anyone links are permitted, an expiration must be set of 30 days or less. Without expiration, a shared anonymous link provides permanent unauthenticated access.",
    "BusinessRisk": "Permanent anonymous links remain valid indefinitely even after an employee leaves or content changes ownership. Once a link is shared in a phishing email, it can be used repeatedly with no expiry.",
    "Remediation": "SharePoint admin center > Policies > Sharing > Anyone links > Check 'These links must expire within this many days' > Set to 30.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-22"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.SPO.1.3"
      ]
    }
  },
  {
    "ControlId": "SPO-1.4",
    "Category": "SharePoint",
    "Title": "External user resharing of content disabled",
    "Severity": "High",
    "Description": "External users must not be able to reshare content they have access to. Resharing allows viral spread of internal documents beyond originally intended recipients.",
    "BusinessRisk": "When external users can reshare, a document shared with one trusted partner can be redistributed to unknown third parties without the content owner's knowledge.",
    "Remediation": "SharePoint admin center > Policies > Sharing > Uncheck 'Allow guests to share items they don\\'t own'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-22",
        "AC-3"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.SPO.1.4"
      ]
    }
  },
  {
    "ControlId": "SPO-1.5",
    "Category": "SharePoint",
    "Title": "Unmanaged device access policy limits or blocks SharePoint access",
    "Severity": "High",
    "Description": "Unmanaged (non-compliant, non-domain-joined) devices must have restricted access to SharePoint \u2014 either web-only read-only access or blocked entirely. Full access from unmanaged devices allows data to be downloaded to devices with no corporate controls.",
    "BusinessRisk": "An employee accessing SharePoint from a personal device with malware, no encryption, or no EDR can download an entire SharePoint library. The device has no corporate controls to prevent data exfiltration.",
    "Remediation": "SharePoint admin center > Policies > Access control > Unmanaged devices > Select 'Allow limited, web-only access' or 'Block access'.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-17",
        "AC-3"
      ],
      "CIS-v8": [
        "6.3"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.SPO.2.1"
      ]
    }
  },
  {
    "ControlId": "SPO-2.1",
    "Category": "SharePoint",
    "Title": "OneDrive default sharing link scoped to organisation",
    "Severity": "Medium",
    "Description": "The default OneDrive sharing link scope must be set to 'organization' or more restrictive. If set to 'anyone', OneDrive files are shared via anonymous links by default.",
    "BusinessRisk": "OneDrive is the primary personal file storage for all M365 users. If the default sharing link is anonymous, every file share made by any user creates a public link unless overridden.",
    "Remediation": "SharePoint admin center > OneDrive settings > Default link type > Set to 'People in your organization'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-22"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ],
      "CISA-SCuBA": [
        "MS.SPO.1.2"
      ]
    }
  },
  {
    "ControlId": "SPO-2.2",
    "Category": "SharePoint",
    "Title": "Guest user resharing of items they do not own disabled",
    "Severity": "Medium",
    "Description": "Guest users must not be permitted to reshare content they have been given access to. This prevents viral distribution of internal content to unknown external parties.",
    "BusinessRisk": "A guest given access to a sensitive document can share it with any email address they choose, including outside the trusted external user list. Content spreads beyond the original sharing decision.",
    "Remediation": "SharePoint admin center > Policies > Sharing > Uncheck 'Guests can share items they don\\'t own'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-22",
        "AC-3"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ]
    }
  },
  {
    "ControlId": "TMS-1.1",
    "Category": "Teams",
    "Title": "Teams external access (federation) restricted",
    "Severity": "Medium",
    "Description": "Teams external access must be disabled or restricted to a specific list of trusted organisations. Open federation allows any Teams user globally to search for and contact your users.",
    "BusinessRisk": "Open federation means any person with a Teams account at any company worldwide can initiate chat sessions with your users. Attackers use federation for social engineering, phishing links, and malware delivery directly into Teams.",
    "Remediation": "Teams admin center > Users > External access > Disable federation or configure a specific allowed domains list.",
    "RemediationLink": "https://admin.teams.microsoft.com",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-17",
        "AC-20"
      ],
      "CIS-M365-v6": [
        "3.1.1"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.TEAMS.1.1"
      ]
    }
  },
  {
    "ControlId": "TMS-1.2",
    "Category": "Teams",
    "Title": "Teams consumer (personal account) federation disabled",
    "Severity": "Medium",
    "Description": "The ability for Teams users to communicate with Teams personal (consumer) accounts must be disabled. Consumer accounts are unmanaged, have no corporate governance, and represent a data exfiltration vector.",
    "BusinessRisk": "Teams consumer accounts (teams.live.com / MSA) are personal accounts with no organisation management. An internal user can share any document with a personal Teams account, bypassing all corporate DLP and retention policies.",
    "Remediation": "Teams admin center > Users > External access > Disable 'Allow users to communicate with Teams accounts that aren\\'t managed by an organization'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-17",
        "CM-7"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.TEAMS.1.2"
      ]
    }
  },
  {
    "ControlId": "TMS-1.3",
    "Category": "Teams",
    "Title": "Anonymous meeting join disabled",
    "Severity": "High",
    "Description": "Anonymous users (unauthenticated, no sign-in required) must not be permitted to join Teams meetings. Anonymous join creates zero audit trail and allows anyone with a meeting link to attend.",
    "BusinessRisk": "Any meeting link forwarded externally or posted publicly allows unauthenticated attendance. There is no record of who attended, no identity to correlate to activity, and sensitive meeting content may be recorded by unknown parties.",
    "Remediation": "Teams admin center > Meetings > Meeting policies > Global > Participants and guests > Disable 'Anonymous users can join a meeting'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-3",
        "AC-17",
        "AU-2"
      ],
      "CIS-M365-v6": [
        "3.2.1"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.TEAMS.2.1"
      ]
    }
  },
  {
    "ControlId": "TMS-1.4",
    "Category": "Teams",
    "Title": "Meeting lobby enabled for external and anonymous users",
    "Severity": "High",
    "Description": "The meeting lobby must be enabled for external and anonymous attendees. AutoAdmittedUsers must not be set to 'Everyone' \u2014 setting that bypasses the lobby for all attendees including unauthenticated users.",
    "BusinessRisk": "When AutoAdmittedUsers is 'Everyone', all attendees including anonymous and external users join meetings directly without host approval. Sensitive discussions proceed before the host realises an unknown party has joined.",
    "Remediation": "Teams admin center > Meetings > Meeting policies > Global > Who can bypass the lobby > Set to 'People in my org' or 'Organizers and co-organizers'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-3"
      ],
      "CIS-M365-v6": [
        "3.2.2"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.TEAMS.2.2"
      ]
    }
  },
  {
    "ControlId": "TMS-1.5",
    "Category": "Teams",
    "Title": "Meeting presenter role restricted to organiser or co-organisers",
    "Severity": "Medium",
    "Description": "The default presenter role in Teams meetings must not allow Everyone to present. External attendees should not have presenter permissions by default.",
    "BusinessRisk": "When anyone can present, external attendees can take control of screen sharing, whiteboard, and presentation controls during a meeting. Attackers or social engineers can use presenter access to deliver malicious content.",
    "Remediation": "Teams admin center > Meetings > Meeting policies > Global > Who can present > Set to 'Organizers and co-organizers' or 'People in my org'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-3"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.TEAMS.2.3"
      ]
    }
  },
  {
    "ControlId": "TMS-1.6",
    "Category": "Teams",
    "Title": "PSTN (dial-in) users bypass lobby disabled",
    "Severity": "Medium",
    "Description": "PSTN callers (dial-in via conference bridge) must be placed in the meeting lobby, not admitted directly. PSTN participants have no identity validation beyond knowing the conference number and PIN.",
    "BusinessRisk": "Conference bridge numbers and PINs are frequently noted in calendar invites. Anyone with the dial-in info \u2014 including an attacker who social-engineered a calendar invite \u2014 joins directly without host approval.",
    "Remediation": "Teams admin center > Meetings > Meeting policies > Global > Participants and guests > Disable 'People dialing in can bypass the lobby'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-3"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ],
      "CISA-SCuBA": [
        "MS.TEAMS.2.4"
      ]
    }
  },
  {
    "ControlId": "TMS-2.1",
    "Category": "Teams",
    "Title": "Third-party cloud storage apps disabled in Teams",
    "Severity": "Low",
    "Description": "Third-party cloud storage integrations (Box, Dropbox, Google Drive, ShareFile) must be disabled in Teams. These integrations allow users to share files from unmanaged storage, bypassing DLP and retention policies.",
    "BusinessRisk": "When users share files from Google Drive or Dropbox in Teams, those files bypass M365 DLP scanning, retention policies, and audit logging. Sensitive content can be exfiltrated to unmanaged external storage without detection.",
    "Remediation": "Teams admin center > Teams apps > Permission policies > Global > Disable Box, Dropbox, Google Drive, ShareFile apps.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  },
  {
    "ControlId": "TMS-2.2",
    "Category": "Teams",
    "Title": "Email integration into Teams channels disabled",
    "Severity": "Low",
    "Description": "The ability to send emails directly to a Teams channel email address must be disabled. Channel email addresses can be discovered or leaked and allow external parties to inject content into Teams channels.",
    "BusinessRisk": "Channel email addresses, once shared or discovered, allow anyone to post messages or files directly into a Teams channel without authentication or MFA. This bypasses all user authentication controls.",
    "Remediation": "Teams admin center > Teams settings > Email integration > Uncheck 'Allow users to send emails to a channel email address'.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  },
  {
    "ControlId": "PVW-1.1",
    "Category": "Purview",
    "Title": "Unified audit log enabled",
    "Severity": "Critical",
    "Description": "The Microsoft 365 unified audit log must be enabled. All user and admin activity across Exchange, SharePoint, Teams, and Entra ID is recorded here. Without it, forensic investigation of any security incident is impossible.",
    "BusinessRisk": "Without audit logging, security incidents cannot be investigated, attackers cannot be detected, and compliance requirements cannot be demonstrated. This is the foundational control that makes all other security monitoring possible.",
    "Remediation": "Purview compliance portal > Audit > Turn on auditing. Or PowerShell: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true",
    "RemediationLink": "https://compliance.microsoft.com/auditlogsearch",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AU-2",
        "AU-12",
        "SI-4"
      ],
      "CIS-v8": [
        "8.2",
        "8.5"
      ],
      "CIS-M365-v6": [
        "6.1.1"
      ],
      "HIPAA": [
        "164.312(b)"
      ],
      "ISO-27001": [
        "A.8.15"
      ],
      "NIST-CSF-2": [
        "DE.CM-09"
      ],
      "SOC-2": [
        "CC7.2"
      ],
      "CISA-SCuBA": [
        "MS.DEFENDER.1.5"
      ]
    }
  },
  {
    "ControlId": "PVW-1.2",
    "Category": "Purview",
    "Title": "Audit log retention configured (90 days minimum)",
    "Severity": "High",
    "Description": "Audit log retention must be configured for a minimum of 90 days. The default retention for M365 E3 is 90 days; E5/Audit Premium extends to 1 year. Incidents discovered weeks after they occur require log data to be present.",
    "BusinessRisk": "Security incidents are often discovered days or weeks after they begin. If audit retention is too short, the evidence needed to understand the scope, entry point, and lateral movement of an attack is gone before investigation begins.",
    "Remediation": "Purview compliance portal > Audit > Audit retention policies > Create policy for 90+ days. For 1-year retention: Microsoft Purview Audit (Premium) or Microsoft 365 E5 license required.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AU-9",
        "AU-11"
      ],
      "CIS-M365-v6": [
        "6.1.2"
      ],
      "HIPAA": [
        "164.312(b)"
      ],
      "ISO-27001": [
        "A.8.15"
      ],
      "NIST-CSF-2": [
        "DE.CM-09"
      ]
    }
  },
  {
    "ControlId": "PVW-2.1",
    "Category": "Purview",
    "Title": "DLP policy covers Exchange email",
    "Severity": "High",
    "Description": "A Data Loss Prevention policy must cover Exchange Online email, scanning for sensitive information types (PII, credit card, SSN, health data). Without DLP on email, sensitive data can be emailed externally without detection.",
    "BusinessRisk": "Email is the most common exfiltration channel. An employee emailing a spreadsheet containing customer PII, credit card numbers, or PHI to a personal account has no controls without email DLP. Regulatory fines under HIPAA, GDPR, and state breach notification laws apply.",
    "Remediation": "Purview compliance portal > Data loss prevention > Policies > Create policy > Use built-in templates (Financial, PII, HIPAA) > Include Exchange as a location.",
    "RemediationLink": "https://compliance.microsoft.com/datalossprevention/policies",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-12",
        "MP-6"
      ],
      "CIS-v8": [
        "3.11"
      ],
      "CIS-M365-v6": [
        "6.3.1"
      ],
      "HIPAA": [
        "164.312(e)"
      ],
      "ISO-27001": [
        "A.8.12"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ]
    }
  },
  {
    "ControlId": "PVW-2.2",
    "Category": "Purview",
    "Title": "DLP policy covers SharePoint and OneDrive",
    "Severity": "High",
    "Description": "A DLP policy must cover SharePoint and OneDrive, scanning stored documents for sensitive information types. Without this, sensitive files can be stored and shared from SharePoint with no data controls.",
    "BusinessRisk": "SharePoint and OneDrive are the primary document repositories for most organisations. Without DLP coverage, a document containing SSNs, medical records, or credit card numbers can be stored, shared externally, and exfiltrated with no detection or blocking.",
    "Remediation": "Purview compliance portal > Data loss prevention > Policies > Create or edit policy > Add SharePoint sites and OneDrive accounts as locations.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-12",
        "AC-3"
      ],
      "CIS-M365-v6": [
        "6.3.2"
      ],
      "HIPAA": [
        "164.312(e)"
      ],
      "ISO-27001": [
        "A.8.12"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ]
    }
  },
  {
    "ControlId": "PVW-2.3",
    "Category": "Purview",
    "Title": "DLP policy covers Microsoft Teams",
    "Severity": "Medium",
    "Description": "A DLP policy must cover Microsoft Teams chat and channel messages. Teams has become a primary communication channel where sensitive data is shared, often without awareness of the persistence of chat history.",
    "BusinessRisk": "Teams messages and shared files are frequently used to exchange sensitive data informally. Without Teams DLP, a chat message containing a credit card number or SSN shared with an external guest is invisible to compliance controls.",
    "Remediation": "Purview compliance portal > Data loss prevention > Policies > Create or edit policy > Add Teams chat and channel messages as a location.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-12"
      ],
      "CIS-M365-v6": [
        "6.3.3"
      ],
      "ISO-27001": [
        "A.8.12"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ]
    }
  },
  {
    "ControlId": "PVW-3.1",
    "Category": "Purview",
    "Title": "Retention policy for Exchange email configured",
    "Severity": "Medium",
    "Description": "A retention policy must be applied to Exchange email. Retention prevents users from permanently deleting evidence relevant to legal holds, eDiscovery, and regulatory compliance. Retention must be configured before a legal hold is needed.",
    "BusinessRisk": "Without email retention, employees can permanently delete emails. When a lawsuit, regulatory investigation, or HR matter arises and email evidence has been deleted, the organisation faces spoliation claims and is unable to defend itself.",
    "Remediation": "Purview compliance portal > Data lifecycle management > Retention policies > Create policy for Exchange email. Set retention period to 3-7 years depending on regulatory requirements.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AU-11",
        "SI-12"
      ],
      "CIS-M365-v6": [
        "6.2.1"
      ],
      "HIPAA": [
        "164.312(b)"
      ],
      "ISO-27001": [
        "A.8.15"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ]
    }
  },
  {
    "ControlId": "PVW-3.2",
    "Category": "Purview",
    "Title": "Retention policy for SharePoint and OneDrive configured",
    "Severity": "Medium",
    "Description": "A retention policy must be applied to SharePoint and OneDrive. Documents must be retained for the regulatory period before deletion is permitted. This protects against permanent loss of business records.",
    "BusinessRisk": "Without document retention, employees can permanently delete business records from SharePoint. Regulatory records (HIPAA, financial records, government contracts) may be required to be retained for 5-7+ years. Permanent deletion creates compliance and litigation risk.",
    "Remediation": "Purview compliance portal > Data lifecycle management > Retention policies > Create policy for SharePoint sites and OneDrive accounts.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AU-11",
        "SI-12"
      ],
      "CIS-M365-v6": [
        "6.2.2"
      ],
      "ISO-27001": [
        "A.8.15"
      ],
      "NIST-CSF-2": [
        "PR.DS-02"
      ]
    }
  },
  {
    "ControlId": "PVW-4.1",
    "Category": "Purview",
    "Title": "Sensitivity labels published to users",
    "Severity": "Medium",
    "Description": "Sensitivity labels must be created and published to users via a label policy. Labels enable data classification, encryption, watermarking, and access control at the document level \u2014 independent of where the document is stored or shared.",
    "BusinessRisk": "Without sensitivity labels, there is no consistent data classification across the organisation. Documents have no inherent protection \u2014 encryption, access restrictions, and watermarks require labels. Classified documents emailed externally, saved to personal storage, or shared with guests have no persistent protection.",
    "Remediation": "Purview compliance portal > Information protection > Labels > Create labels (Public, Internal, Confidential, Highly Confidential). Publish via Information protection > Label policies.",
    "EffortLevel": "Strategic (planning required)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-16",
        "MP-3"
      ],
      "CIS-M365-v6": [
        "6.4.1"
      ],
      "ISO-27001": [
        "A.5.12",
        "A.8.2"
      ],
      "NIST-CSF-2": [
        "PR.DS-01"
      ],
      "CISA-SCuBA": [
        "MS.PURVIEW.1.1"
      ]
    }
  },
  {
    "ControlId": "ITN-1.1",
    "Category": "Intune",
    "Title": "Intune MDM authority configured and devices enrolled",
    "Severity": "High",
    "Description": "Microsoft Intune must be configured as the MDM authority and devices must be enrolled. Without Intune, there is no centralised endpoint management, compliance enforcement, or remote wipe capability.",
    "BusinessRisk": "Without MDM, there is no way to enforce security baselines on endpoints, push patches, remote wipe lost devices, or verify device compliance before granting access. Any device with valid credentials can access corporate data regardless of its security state.",
    "Remediation": "Microsoft 365 admin center > Endpoint Manager > Set MDM authority to Intune. Enroll devices via Autopilot, Group Policy, or the Company Portal app.",
    "RemediationLink": "https://endpoint.microsoft.com",
    "EffortLevel": "Strategic (planning required)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-2",
        "CM-6"
      ],
      "CIS-v8": [
        "4.1",
        "5.1"
      ],
      "ISO-27001": [
        "A.8.9"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  },
  {
    "ControlId": "ITN-1.2",
    "Category": "Intune",
    "Title": "Windows device compliance policy requires BitLocker encryption",
    "Severity": "High",
    "Description": "The Windows device compliance policy must require BitLocker (or equivalent) disk encryption. Without this, a non-encrypted device is considered compliant and retains access to corporate data even if lost or stolen.",
    "BusinessRisk": "An unencrypted laptop contains all locally cached corporate data, emails, and credentials in plaintext. If stolen, all data is immediately accessible without any credential. Regulatory requirements (HIPAA, government contracts) typically mandate encryption of devices handling sensitive data.",
    "Remediation": "Endpoint Manager > Devices > Compliance policies > [Windows policy] > Device health > Require BitLocker = Require.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SC-28",
        "SC-28(1)"
      ],
      "CIS-v8": [
        "3.6"
      ],
      "HIPAA": [
        "164.312(a)(2)(iv)"
      ],
      "ISO-27001": [
        "A.8.24"
      ],
      "NIST-CSF-2": [
        "PR.DS-01"
      ]
    }
  },
  {
    "ControlId": "ITN-1.3",
    "Category": "Intune",
    "Title": "Windows device compliance policy requires antivirus and firewall",
    "Severity": "High",
    "Description": "The Windows device compliance policy must require both antivirus (Defender or equivalent) and Windows Firewall to be active. Devices without these controls should be marked non-compliant and denied access.",
    "BusinessRisk": "A device without active antivirus is vulnerable to malware that can steal credentials, install ransomware, and serve as a pivot point into the corporate network. Without compliance enforcement, infected devices retain full access to M365 services.",
    "Remediation": "Endpoint Manager > Devices > Compliance policies > [Windows policy] > System security: Firewall = Required, Antivirus = Required, Real-time protection = Required.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-3",
        "SC-7"
      ],
      "CIS-v8": [
        "4.5",
        "9.4"
      ],
      "ISO-27001": [
        "A.8.7"
      ],
      "NIST-CSF-2": [
        "DE.CM-01",
        "PR.PS-05"
      ]
    }
  },
  {
    "ControlId": "ITN-1.4",
    "Category": "Intune",
    "Title": "iOS App Protection (MAM) policy configured",
    "Severity": "High",
    "Description": "An App Protection Policy (MAM) must be configured for iOS devices covering corporate apps (Outlook, Teams, OneDrive). MAM applies corporate data controls to apps on personal devices without requiring full device enrollment.",
    "BusinessRisk": "Without iOS MAM, employees accessing corporate email and files on personal iPhones have no corporate controls. Corporate data can be copied to personal apps, screenshots taken, and data cannot be remotely wiped when the employee leaves.",
    "Remediation": "Endpoint Manager > Apps > App protection policies > Create policy (iOS/iPadOS). Assign to corporate apps. Set PIN, copy/paste restriction, backup to personal storage blocked, remote wipe enabled.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7",
        "SC-4"
      ],
      "CIS-v8": [
        "4.2"
      ],
      "ISO-27001": [
        "A.8.9"
      ],
      "NIST-CSF-2": [
        "PR.DS-01"
      ]
    }
  },
  {
    "ControlId": "ITN-1.5",
    "Category": "Intune",
    "Title": "Android App Protection (MAM) policy configured",
    "Severity": "High",
    "Description": "An App Protection Policy (MAM) must be configured for Android devices covering corporate apps. Android is the most common mobile platform and highest-risk for data leakage without MAM controls.",
    "BusinessRisk": "Android's open app ecosystem makes it particularly vulnerable to side-loaded apps that can intercept data from corporate apps. Without MAM, a corporate document opened in Outlook on an Android device can be shared to any personal app.",
    "Remediation": "Endpoint Manager > Apps > App protection policies > Create policy (Android). Assign to corporate apps. Set PIN, restrict copy/paste to managed apps, block screenshots, enable remote wipe.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7",
        "SC-4"
      ],
      "CIS-v8": [
        "4.2"
      ],
      "ISO-27001": [
        "A.8.9"
      ],
      "NIST-CSF-2": [
        "PR.DS-01"
      ]
    }
  },
  {
    "ControlId": "ITN-1.6",
    "Category": "Intune",
    "Title": "Windows Hello for Business policy configured in Intune",
    "Severity": "Medium",
    "Description": "Windows Hello for Business (WHfB) must be configured via Intune policy. WHfB provides phishing-resistant, biometric-backed device sign-in that replaces passwords at the OS level on enrolled Windows devices.",
    "BusinessRisk": "Windows devices signing in with passwords are vulnerable to credential theft, Pass-the-Hash, and LSASS attacks. WHfB uses asymmetric cryptography with the device TPM \u2014 there is no password to steal or replay.",
    "Remediation": "Endpoint Manager > Devices > Enrollment > Windows Hello for Business > Enable. Set minimum PIN length, require biometric, require TPM. Alternatively create Identity Protection device configuration profile.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "IA-2(8)",
        "IA-5(2)"
      ],
      "CIS-v8": [
        "6.5"
      ],
      "ISO-27001": [
        "A.8.5"
      ],
      "NIST-CSF-2": [
        "PR.AA-03"
      ]
    }
  },
  {
    "ControlId": "ITN-1.7",
    "Category": "Intune",
    "Title": "Microsoft Defender for Endpoint connector enabled in Intune",
    "Severity": "High",
    "Description": "The Microsoft Defender for Endpoint (MDE) connector must be enabled in Intune and integrated with device compliance. MDE threat risk scores feed into Intune compliance evaluation, allowing at-risk devices to be automatically blocked from accessing corporate data.",
    "BusinessRisk": "Without the MDE-Intune connector, a device actively compromised by malware remains 'compliant' in Intune and retains full access to M365. The threat intelligence MDE generates cannot result in automated access revocation.",
    "Remediation": "Requires MDE Plan 1 or Plan 2. Endpoint Manager > Endpoint security > Microsoft Defender for Endpoint > Open MDE console and enable the Intune connection. Return to Intune and enable connector. Add MDE risk level to compliance policy.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "SI-3",
        "SI-4"
      ],
      "CIS-v8": [
        "10.1"
      ],
      "ISO-27001": [
        "A.8.7"
      ],
      "NIST-CSF-2": [
        "DE.CM-01",
        "RS.AN-03"
      ]
    }
  },
  {
    "ControlId": "ITN-2.1",
    "Category": "Intune",
    "Title": "Enrollment restrictions configured beyond default allow-all policy",
    "Severity": "Medium",
    "Description": "Custom enrollment restrictions must be configured to control which device types and platforms can enroll in Intune. The default policy allows all platforms and all users to enroll any device type.",
    "BusinessRisk": "Without enrollment restrictions, any device \u2014 including personal devices and platforms not supported by the organisation \u2014 can enroll in Intune. This creates unmanaged scope and may allow non-compliant device types to enroll and appear compliant.",
    "Remediation": "Endpoint Manager > Devices > Enrollment restrictions > Create restriction. Block platforms not in use (e.g., macOS if org is Windows-only). Restrict to corporate-owned if BYOD is not permitted.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7",
        "AC-3"
      ],
      "CIS-v8": [
        "4.1"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  },
  {
    "ControlId": "PPL-1.1",
    "Category": "Power Platform",
    "Title": "Default environment DLP policy configured",
    "Severity": "High",
    "Description": "A Data Loss Prevention (DLP) policy must cover the default Power Platform environment. The default environment is accessible to all licensed M365 users and has no security controls without an explicit DLP policy.",
    "BusinessRisk": "Every M365 user can create Power Apps and Power Automate flows in the default environment. Without a DLP policy, flows can connect to any external service \u2014 HTTP endpoints, consumer apps, social media \u2014 and exfiltrate corporate data with no controls.",
    "Remediation": "Power Platform admin center > Policies > Data policies > Create policy. Apply to Default environment. Place HTTP connector and Custom connector in Blocked group. Separate Business from Non-Business connectors.",
    "RemediationLink": "https://admin.powerplatform.microsoft.com",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7",
        "AC-3"
      ],
      "CIS-v8": [
        "3.3"
      ],
      "ISO-27001": [
        "A.8.9"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  },
  {
    "ControlId": "PPL-1.2",
    "Category": "Power Platform",
    "Title": "Power Platform tenant isolation enabled",
    "Severity": "Medium",
    "Description": "Tenant isolation must be enabled to prevent cross-tenant data flow in Power Platform. Without isolation, Power Automate flows and Power Apps in this tenant can connect to and pull data from other tenants.",
    "BusinessRisk": "Without tenant isolation, an internal user can create a flow that queries data from a partner or competitor's tenant if they have credentials for that tenant. Cross-tenant data aggregation is difficult to detect and creates data sovereignty issues.",
    "Remediation": "Power Platform admin center > Policies > Tenant isolation > Enable. Add trusted partner tenants to the allowlist for permitted cross-tenant connections.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-17",
        "AC-3"
      ],
      "ISO-27001": [
        "A.8.9"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ]
    }
  },
  {
    "ControlId": "PPL-1.3",
    "Category": "Power Platform",
    "Title": "High-risk connectors blocked in Power Platform DLP policies",
    "Severity": "Medium",
    "Description": "DLP policies must place HTTP, HTTPWithAzureAD, and Custom connectors in the Blocked group. These connectors allow arbitrary external HTTP requests and effectively bypass all other DLP restrictions.",
    "BusinessRisk": "The HTTP connector in Power Automate allows flows to make arbitrary web requests to any URL. A flow can exfiltrate an entire SharePoint library by iterating through files and POSTing contents to an external server. This is undetectable without DLP blocking.",
    "Remediation": "Power Platform admin center > Policies > [DLP Policy] > Edit > Blocked group > Add HTTP, HTTPWithAzureAD, HTTP with Azure AD, and Custom connectors.",
    "EffortLevel": "Quick Win (< 30 min)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7"
      ],
      "ISO-27001": [
        "A.8.9"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  },
  {
    "ControlId": "PPL-2.1",
    "Category": "Power Platform",
    "Title": "Power Platform admin role assignments minimal",
    "Severity": "Medium",
    "Description": "The Power Platform Administrator and Dynamics 365 Administrator role assignments must be minimal \u2014 3 or fewer. These roles provide full control over all Power Platform environments, DLP policies, and connections.",
    "BusinessRisk": "Power Platform admins can modify or delete DLP policies, create environments without restrictions, and access data in all Power Platform environments. Excessive admin assignments increase the blast radius of a compromised admin account.",
    "Remediation": "Entra ID > Roles > Power Platform Administrator > Review and reduce assignments. Migrate to PIM eligible assignments where P2 is available.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "AC-6(5)",
        "AC-2"
      ],
      "CIS-v8": [
        "5.4"
      ],
      "NIST-CSF-2": [
        "PR.AA-05"
      ]
    }
  },
  {
    "ControlId": "PPL-2.2",
    "Category": "Power Platform",
    "Title": "Non-default Power Platform environments covered by DLP policy",
    "Severity": "Medium",
    "Description": "All non-default Power Platform environments (production, sandbox, developer) must be explicitly covered by at least one DLP policy. Environments without DLP have no connector restrictions.",
    "BusinessRisk": "Non-default environments are often created for specific projects or departments and may contain production data. Without DLP, connectors in these environments can freely access and exfiltrate data. Shadow IT environments created without IT knowledge are common.",
    "Remediation": "Power Platform admin center > Policies > Data policies > Review each policy scope. Ensure every non-default environment appears in at least one policy scope.",
    "EffortLevel": "Standard (1-4 hrs)",
    "Frameworks": {
      "NIST-800-53": [
        "CM-7",
        "AC-3"
      ],
      "NIST-CSF-2": [
        "PR.PS-01"
      ]
    }
  }
]

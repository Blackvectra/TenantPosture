# NRG-Assessment Tool — Claude Code Project Context

**Author:** Matthew Levorson, NRG Technology Services / NextLayerSec LLC
**GitHub:** https://github.com/Blackvectra/NRG-Assessment-Tool
**Version:** 4.5.5
**Language:** PowerShell 7.0+
**Purpose:** Read-only Microsoft 365 security assessment framework for MSP multi-tenant environments.

## What This Tool Does

NRG-Assessment runs agentlessly against any Microsoft 365 tenant, collects security configuration data via Microsoft Graph and Exchange Online PowerShell, evaluates 188 controls against a license-aware baseline, and produces an interactive HTML report with executive summary, compliance matrix, attack scenario analysis, and NRG services pitch. It is a read-only assessment — it never modifies tenant configuration.

There are two entry points. `Invoke-NRGAssessment.ps1` runs against a single tenant interactively. `Invoke-NRGBatchAssessment.ps1` runs against all clients defined in `Config/clients.json` sequentially using GDAP delegated access, producing per-client reports and a batch summary.

## Project Structure

`NRG-Assessment-Tool/` contains `Invoke-NRGAssessment.ps1` (single-tenant entry point), `Invoke-NRGBatchAssessment.ps1` (multi-tenant batch entry point), `NRG-Assessment.psm1` (module loader that dot-sources all subdirectories recursively), and `NRG-Assessment.psd1` (module manifest).

`Lib/` contains `Add-NRGFinding.ps1` (state management: findings, raw data, coverage, Clear-NRGState), `Connect-NRGServices.ps1` (Graph + EXO + Teams + IPPSSession connection logic), and `Get-NRGBaselineTier.ps1` (license detection and baseline compliance functions).

`Collectors/` contains one file per workload and is recursively loaded by the psm1. `AAD/` contains `Invoke-NRGCollectAADInventory.ps1` (sets `AAD-Inventory`), `Invoke-NRGCollectAADUsers.ps1` (sets `AAD-Users`), `Invoke-NRGCollectAADAuthPolicies.ps1` (sets `AAD-AuthPolicies` and `AAD-CAPolicies`), `Invoke-NRGCollectAADCAPolicies.ps1` (wrapper to AuthPolicies), `Invoke-NRGCollectAADRoles.ps1` (sets `AAD-DirectoryRoles`, `AAD-PIMSchedules`, `AAD-IdentityGovernance`), `Invoke-NRGCollectAADPIM.ps1` (wrapper to Roles), and `Invoke-NRGCollectAADIdentityGovernance.ps1` (wrapper to Roles). `EXO/` contains `Invoke-NRGCollectEXOMailboxConfig.ps1` (sets `EXO-MailboxConfig`) and `Invoke-NRGCollectEXOConnectionFilter.ps1` (sets `EXO-ConnectionFilter`). `Defender/` contains `Invoke-NRGCollectDefender.ps1` (sets `Defender-Policies`). `DNS/` contains `Invoke-NRGCollectDNSEmailRecords.ps1` (sets `DNS-domain` and `DNS-Summary`). `Teams/` contains `Invoke-NRGCollectTeams.ps1` (sets `Teams`). `SharePoint/` contains `Invoke-NRGCollectSharePoint.ps1` (sets `SharePoint`). `Intune/` contains `Invoke-NRGCollectIntune.ps1` (sets `Intune`). `Purview/` contains `Invoke-NRGCollectPurview.ps1` (sets `Purview`). `PowerPlatform/` contains `Invoke-NRGCollectPowerPlatform.ps1` (sets `PowerPlatform`).

`Evaluators/` contains one file per workload, each function evaluating one control: `Test-NRGControl-AAD.ps1` (41 functions), `Test-NRGControlDefender.ps1` (18 functions), `Test-NRGControlTeams.ps1` (17 functions), `Test-NRGControlPurview.ps1` (15 functions), `Test-NRGControlSharePoint.ps1` (13 functions), `Test-NRGControlIntune.ps1` (13 functions), `Test-NRGControlCopilot.ps1` (5 functions), `Test-NRGControlPowerPlatform.ps1` (4 functions).

`Publishers/` contains `Publish-NRGAssessmentHTML.ps1` (1682-line interactive HTML report generator).

`Config/` contains `clients.json` (batch client list with TenantId, DelegatedOrg, and skip flags), `controls.json` (control definitions with id, title, severity, and framework IDs), and `baselines/` containing `nrg-baseline-basic.json` (106 controls, 8 workload config sections), `nrg-baseline-standard.json` (15 controls, 4 workload config sections), `nrg-baseline-premium.json` (35 controls, 4 workload config sections), and `nrg-baseline-e5.json` (32 controls, 6 workload config sections).

## Control Architecture

188 total controls across 9 workloads: Azure AD / Entra ID (AAD, 46), Exchange Online (EXO, 28), Defender for Office 365 (DEF, 23), Microsoft Teams (TMS, 22), Purview / Compliance (PVW, 18), SharePoint Online (SPO, 17), Microsoft Intune (INT, 17), Power Platform (PPL, 11), Email Auth DNS (DNS, 6). Severity breakdown: 12 Critical, 88 High, 61 Medium, 27 Low.

Baseline tiers follow an `InheritsFrom` chain with zero overlap between tiers. `nrg-baseline-basic` covers 106 controls for any tenant. `nrg-baseline-standard` adds 15 controls (121 total) for Microsoft 365 Business Standard. `nrg-baseline-premium` adds 35 controls (156 total) for Business Premium and Entra P1/P2. `nrg-baseline-e5` adds 32 controls (188 total) for Microsoft 365 E5, Defender P2, and Purview Premium.

License detection runs via `SubscribedSkus` in `Get-NRGBaselineTier.ps1`. Only controls applicable to the detected tier count toward the compliance score. Premium and E5 controls on lower-tier tenants route to the Upgrade Unlocks section of the HTML report.

## Data Flow

`Connect-NRGServices` establishes Graph (21 scopes) plus EXO, Teams (optional), and IPPSSession (optional). Collectors run first and populate module-scope raw data using `Set-NRGRawData` with a key per workload. Each result object has `CollectorId`, `CollectedAt`, `Success`, and `Data`. Evaluators read raw data using `Get-NRGRawData` and write findings using `Add-NRGFinding` with states of `Satisfied`, `Gap`, `Partial`, `NotApplicable`, or `Error`. Publishers consume findings via `Get-NRGFindings`, calculate the license-aware score via `Get-NRGBaselineTier`, and produce the HTML report and JSON export.

Raw data keys and their collectors: `AAD-Inventory` set by `Invoke-NRGCollectAADInventory`; `AAD-Users` set by `Invoke-NRGCollectAADUsers`; `AAD-AuthPolicies` set by `Invoke-NRGCollectAADAuthPolicies`; `AAD-CAPolicies` set by `Invoke-NRGCollectAADAuthPolicies` via wrapper; `AAD-DirectoryRoles`, `AAD-PIMSchedules`, `AAD-IdentityGovernance` all set by `Invoke-NRGCollectAADRoles` via wrappers; `EXO-MailboxConfig` set by `Invoke-NRGCollectEXOMailboxConfig`; `EXO-ConnectionFilter` set by `Invoke-NRGCollectEXOConnectionFilter`; `Defender-Policies` set by `Invoke-NRGCollectDefender`; `DNS-domain` and `DNS-Summary` set by `Invoke-NRGCollectDNSEmailRecords`; `Teams` set by `Invoke-NRGCollectTeams`; `SharePoint` set by `Invoke-NRGCollectSharePoint`; `Intune` set by `Invoke-NRGCollectIntune`; `Purview` set by `Invoke-NRGCollectPurview`; `PowerPlatform` set by `Invoke-NRGCollectPowerPlatform`.

## Module State

All state is module-scope and cleared between batch clients by `Clear-NRGState`, which resets four variables: `NRGFindings` (List of hashtable), `NRGRawData` (Dictionary), `NRGCoverage` (Dictionary), and `NRGExceptions` (List of hashtable). `Clear-NRGState` must be called between batch clients or raw data from one client bleeds into the next client's evaluation.

## Coding Standards

Every script file requires a header block with `#Requires -Version 7.0`, the filename, NRG Technology Services / NextLayerSec LLC, Author: Matthew Levorson, a one-line purpose statement, the data keys set or consumed, and the Graph scopes or cmdlets required.

All functions use `[CmdletBinding()]`. All data structures that get serialized use `[ordered]` hashtables. All external API calls use `ErrorAction Stop` and are wrapped in `try/catch` with `Register-NRGException`. `Write-Host` is never used in collectors or evaluators — use `Write-Verbose` only. No hardcoded credentials, tenant IDs, or domain names in code. Exit codes are 0 for success, 1 for auth failure, 2 for no findings, 3 for partial collection, 4 for fatal error.

Every collector must initialize a result object with `CollectorId`, `CollectedAt`, `Success` set to `false`, and a `Data` block; execute API calls inside `try/catch`; set `Success` to `true` on completion; call `Set-NRGRawData`; and call `Register-NRGCoverage`.

Every evaluator must guard against missing data as its first action. If `Get-NRGRawData` returns null or `Success` is false, register `NotApplicable` and return immediately. Never allow a null reference to propagate into evaluation logic. `Add-NRGFinding` accepts `ControlId`, `State`, `Category`, `Title`, `Severity`, `Detail`, `FrameworkIds`, `CurrentValue`, `RequiredValue`, and `RemediationSteps`.

## Baseline Configuration Schema

Each baseline JSON has two sections: `RequiredControls` (list of control IDs applicable at this tier) and `Configuration` (prescriptive settings organized by workload). Each Configuration entry contains `ControlId`, `Setting`, `RequiredValue`, `Rationale`, `Authority`, and `RemediationCmdlet`. When adding new controls, add the ID to exactly one tier's `RequiredControls`, add the Configuration entry to the same file, and verify no duplicates exist across all four tier files.

## Graph Scopes (21 total)

`Application.Read.All`, `AuditLog.Read.All`, `DeviceManagementApps.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementServiceConfig.Read.All`, `Directory.Read.All`, `Group.Read.All`, `IdentityRiskyUser.Read.All`, `Organization.Read.All`, `Policy.Read.All`, `Policy.Read.PermissionGrant`, `Reports.Read.All`, `RoleManagement.Read.All`, `SecurityEvents.Read.All`, `SharePointTenantSettings.Read.All`, `Sites.Read.All`, `TeamSettings.Read.All`, `User.Read.All`, `UserAuthenticationMethod.Read.All`, `PrivilegedAccess.Read.AzureAD`.

Do not add scopes without updating `Connect-NRGServices.ps1`. The scope list must remain in sync with the enterprise app registration in each client tenant.

## Batch Mode

`Config/clients.json` requires the following fields for every client: `ClientName`, `TenantDomain`, `TenantId` (GUID), `DelegatedOrg` (the `.onmicrosoft.com` routing domain — not the primary domain), `UserPrincipalName`, `ClientType` (`Contract`, `NonContract`, or `Prospect`), `NRGHourlyRate`, `DnsDomains` (array), `SkipPurview`, `SkipTeams`, `SkipSharePoint`, `SkipIntune`, `SkipPowerPlatform`, `SkipDNS` (all boolean), `Notes`, and `Active`.

`DelegatedOrg` must be the `.onmicrosoft.com` routing domain. Get it from Microsoft 365 Admin Center under Settings then Domains for each client. Get `TenantId` from `https://login.microsoftonline.com/domain/.well-known/openid-configuration` — the GUID in the issuer field is the TenantId.

Test sequence before first full run: run with `-WhatIf` first, then `-OnlyClient nextlayersec.io -JsonOnly`, then full batch.

## HTML Report Structure

The report produces 13 sections: Executive Overview with score ring and license tier badge; Framework Compliance Matrix covering CIS M365 v6, CISA SCuBA, NIST 800-53r5, and CMMC 2.0; NRG Baseline Compliance with tier-detected score and deviation table; License Gap Analysis; Priority Actions with current state and business risk per finding; Additional Gaps for Medium findings; Attack Scenario Analysis for BEC, Ransomware, Domain Spoofing, and Privilege Escalation; What's Working; NRG Services and Quote; Security Roadmap; Named Findings; Upgrade Unlocks; and All Findings. Report modes are `-ClientType` (`Contract`, `NonContract`, or `Prospect`), and `-NRGHourlyRate` to override the default rate of 150.

## Known Gaps and Roadmap

**Phase 2 priorities** are: extending `Invoke-NRGCollectDNSEmailRecords` with DKIM key rotation age via `Get-DkimSigningConfig`, CAA record validation, TLS certificate expiry on mail hostnames, and CT log checks via `crt.sh`; creating `Invoke-NRGCollectEXOInventory` for external forwarding rules, shared mailbox sign-in state, per-user audit exceptions, and SMTP AUTH per-user overrides; populating real CISA ScubaGear rule identifiers into `controls.json` `FrameworkIds` fields from https://github.com/cisagov/ScubaGear; and creating dedicated evaluator files `Test-NRGControlEXO.ps1` and `Test-NRGControlDNS.ps1` which currently do not exist.

**Phase 3** covers delta and drift detection comparing current run JSON against a prior snapshot for CA policy changes, new admin role assignments, new OAuth app registrations, and DMARC policy regression; a Markdown summary publisher for ConnectWise ticket output; and a remediation playbook publisher consuming baseline `RemediationCmdlet` fields.

**Phase 4** covers `Apply-NRGBaseline.ps1` as a write-mode deployment script with mandatory `WhatIf` support and `-Confirm` required for auth policy or admin role changes; Windows LAPS (INT-4.1) and Windows Hello for Business (INT-4.2) evaluators; and implementation of the five Copilot governance controls which currently return `NotApplicable`.

## Environment

MSP context is NRG Technology Services, North Dakota. Government clients have CISA BOD 18-01 compliance obligations. Key clients are `nrgtechservices.com`, `clienta.org`, and `clientbnd.gov`. Tooling includes ConnectWise RMM, Cortex XDR, Microsoft Defender for Endpoint, SonicWall, DMARCian, and Microsoft 365/Entra ID. Frameworks referenced are NIST SP 800-53r5, NIST CSF 2.0, MITRE ATT&CK Enterprise, CIS M365 Foundations v3, CISA SCuBA, and CISA BOD 18-01. Logs go to `C:\ProgramData\NRG\Logs`. Assessment output goes to `.\output\tenantdomain\timestamp-results.json`. Batch summary goes to `.\output\batch-summary-timestamp.md`.

## Common Tasks

**To add a new control:** add the definition to `controls.json`, add the ID to exactly one tier's `RequiredControls`, add the Configuration entry with `RequiredValue` and `RemediationCmdlet` to the same baseline file, add the evaluator function to the appropriate evaluator file, and verify the collector sets the data field the evaluator reads.

**To add a new client:** get the `TenantId` from the OpenID configuration endpoint, confirm the `.onmicrosoft.com` routing domain from M365 Admin Center, add the entry to `clients.json`, and set Skip flags based on the client's license tier — set `SkipPurview` and `SkipPowerPlatform` for Business Standard clients.

**To debug a collector:** run `-JsonOnly`, open the output JSON, find the collector key under `RawData`, check the `Success` field and `CollectedAt` timestamp, and check the `Exceptions` array for registered errors.

**To debug a wrong evaluator result:** confirm what raw data key it reads, verify the collector set `Success` to `true`, and inspect the specific fields the evaluator accesses against the actual collected data. Evaluators must never crash on missing fields — use null-conditional operators or explicit null checks throughout.

## Security Requirements

The tool is **read-only without exception**. No evaluator, collector, or publisher may write to tenant configuration. All Graph calls use GET only. All EXO calls use read-only cmdlets only. Any future write capability belongs exclusively in `Apply-NRGBaseline.ps1` with mandatory `WhatIf` support. Raw data is stored in module-scope memory only and never written to disk unencrypted. JSON output must not include credentials, tokens, or user PII beyond UPN and display name.

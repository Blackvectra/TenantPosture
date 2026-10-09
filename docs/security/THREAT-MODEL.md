# Threat Model — TenantPosture v4.5.5

## Scope

This threat model covers the TenantPosture PowerShell module and its execution environment. It does not cover the M365 tenants being assessed — that is what the tool assesses.

---

## Trust Boundaries

### Trusted
- PowerShell 7.x runtime (installed, version-verified by `#Requires`)
- Microsoft Graph SDK, ExchangeOnlineManagement, Teams, SharePoint modules (version-pinned at install time)
- `$PSScriptRoot` — the tool's own directory

### Untrusted / Attacker-Controlled
- **Tenant data returned from Graph API** — any string value from a tenant could contain injection payloads
- **controls.json** — file on disk, could be modified by an attacker with local access
- **clients.json** — file on disk, TenantId/DelegatedOrg values processed before auth calls
- **OutputPath / ClientsFile** — CLI parameters, path traversal attempts possible
- **DNS responses** — Resolve-DnsName results treated as hostile data

---

## Attack Vectors Considered

### T1: Tenant Data Injection (XSS via HTML Report)
**Vector:** Tenant admin creates a display name, domain, or policy name containing `<script>alert(1)</script>`  
**Mitigated by:** All tenant-sourced strings pass through `ConvertTo-TPHtmlSafe` before HTML rendering. `hx()` wrapper enforces this in the publisher. Publisher fails closed if `ConvertTo-TPHtmlSafe` is not loaded.  
**Residual:** None — defense-in-depth at both collection (typed PS objects) and publication (HTML escaping) layers.

### T2: Path Traversal via OutputPath
**Vector:** `.\Invoke-TPAssessment.ps1 -OutputPath '../../etc/evil'`  
**Mitigated by:** `[ValidateScript]` on `OutputPath` rejects `../` sequences. Runtime check verifies resolved path stays within intended output directory before writing files.  
**Residual:** None within the tool's code path.

### T3: controls.json Tampering
**Vector:** Attacker with local write access modifies controls.json to inject `<script>` into Remediation strings or creates ControlId `"../../config"` to cause path confusion  
**Mitigated by:** Full content validation on load — Severity/Workload/Category allowlists, ControlId regex, Remediation injection scan, path traversal pattern check on ControlId, prefix/workload consistency. Any failure throws before any evaluator runs.  
**Residual:** If attacker has write access to the tool directory, they already have arbitrary code execution — controls.json defense is hardening-in-depth.

### T4: DNS Cache Poisoning
**Vector:** Poisoned DNS response returns attacker-controlled TXT/CNAME for SPF/DKIM/DMARC lookups  
**Mitigated by:** DNS results are stored as raw strings and scored by evaluators — no code is executed from DNS responses. The tool reports what is in DNS, not what should be. Poisoned results would produce a false Satisfied finding.  
**Residual:** DNS cache poisoning would produce misleading findings, not code execution. Noted as accepted residual.

### T5: Token Exfiltration via Module Load
**Vector:** Malicious PS module in `$env:PSModulePath` intercepts Graph token during Connect-MgGraph  
**Mitigated by:** `-ContextScope Process` limits MSAL token cache scope to the current process. `$env:MSAL_ALLOW_BROKER = '0'` disables WAM broker. `#Requires -Modules` with version pinning reduces substitution risk.  
**Residual:** Module substitution attacks against a process with local code execution are accepted.

### T6: clients.json GUID Injection
**Vector:** Malformed TenantId in clients.json causes unexpected behavior in `Connect-MgGraph -TenantId`  
**Mitigated by:** TenantId validated as GUID format `^[0-9a-fA-F]{8}-...` before any auth call. DelegatedOrg validated as FQDN before `Connect-ExchangeOnline -DelegatedOrganization`.  
**Residual:** None — invalid values fail fast with clear error before any tenant connection.

---

## Accepted Residuals

| ID | Residual | Rationale |
|---|---|---|
| R1 | DNS cache poisoning produces false Satisfied findings | Requires network-level attacker. Accepted — tool is a point-in-time snapshot, not a continuous monitor. |
| R2 | Tenant admin with sufficient permission can create misleading display names to cause false gap/satisfied labels | Requires admin-level access to tenant. If the admin is malicious, the finding is moot. |
| R3 | HTML report on an attacker-controlled web server could be served without the Content-Security-Policy header | Report is a local HTML file — serving it via a web server requires deliberate action outside the tool. |
| R4 | `Set-StrictMode` does not prevent logic errors, only variable initialization issues | Defense-in-depth only. Full logic testing via Pester. |

---

## Supply Chain Risk

| Component | Version Pinned | Integrity Check |
|---|---|---|
| Microsoft.Graph.Authentication | 2.20.0 | PSResourceGet SHAsum |
| ExchangeOnlineManagement | 3.4.0 | PSResourceGet SHAsum |
| MicrosoftTeams | 6.4.0 | PSResourceGet SHAsum |
| Pester | 5.6.1 | PSResourceGet SHAsum |
| TenantPosture itself | v4.5.5 git tag | CycloneDX SBOM on release |

Gitleaks and TruffleHog run on every push to detect accidentally committed credentials.

---

*Last reviewed: May 2026 · NRG Technology Services / NextLayerSec LLC · NRG Technology Services / NextLayerSec LLC*

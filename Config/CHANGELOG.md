# Changelog

## v4.0.0 — 2026-05-11

**Complete architectural rebuild.** v3 is retired due to unresolvable architecture issues (duplicate function definitions, mixed concerns, brittle property dependencies).

### Architecture
- **Strict separation of concerns:** Collectors only collect, Evaluators only score, Publishers only report. Each function has one source file. No duplicates.
- **JSON-driven control definitions** (`Config/controls.json`) — adding a control is a JSON edit, not a code change.
- **JSON-driven framework crosswalk** (`Config/frameworks.json`) — adding a compliance framework is a JSON edit.
- **Module-scoped state** — findings, exceptions, coverage, raw data live in module scope. No globals, no script-wide variables across files.
- **Standard collector schema** — every collector returns `@{ Source; Timestamp; Success; Data; Exceptions }`. Evaluators check `Success` before reading `Data`.

### Authentication
- **Device code for all services.** Works in any terminal, no browser pop-ups, no PnP module quirks.
- **PnP.PowerShell as primary SharePoint module.** Microsoft.Online.SharePoint.PowerShell is fallback only.
- **Explicit `Import-Module MicrosoftTeams`** before connect — fixes PS7 command-not-recognized issues.
- **Connection failures are non-fatal.** A failed connection registers an exception and skips that domain's collectors; other domains continue.

### Initial control set (Phase 1)
11 controls across 3 domains:
- AAD: Block legacy auth, phishing-resistant MFA for privileged roles, PIM usage
- EXO: Mailbox audit enablement, SMTP AUTH disabled, DMARC enforcement
- Defender: Anti-phish impersonation protection, Safe Attachments, Safe Links
- DNS: SPF, DKIM, DMARC at p=reject

Each control includes:
- Business risk statement
- Remediation steps
- Effort level estimate
- Framework citations across 11 frameworks (NIST 800-53, CIS v8, CIS M365 v6, HIPAA, HIPAA NPRM, ISO 27001, NIST CSF 2.0, SOC 2, CISA SCuBA, CISA BOD, CMMC L2)

### Removed from v3 (intentionally)
- 18 duplicate function definitions across Public/*.ps1 and Modules/Nrg_*.psm1
- Mixed collector + scoring + citation logic per file
- Hardcoded control definitions in PowerShell
- Brittle property dependencies (HighConfidencePhishAction direct access, IsBuiltInSystemPolicy compares, HashSet null .ctor exceptions)
- Inconsistent Get-Mg* result handling (unwrapped arrays, .Count on potential null)
- Mixed PowerShell 5.1 / 7.x compatibility assumptions

### Coming in next sessions
- Phase 2: Full identity layer (~80 controls)
- Phase 3: Email + Defender depth (~150 controls)
- HTML report publisher (replaces v3 HTML)
- Technical report publisher (replaces v3 technical)
- Implementation playbook publisher (replaces v3 playbook)
- Phase 4-6: SharePoint, Teams, Purview, Power Platform, Intune, Defender XDR, STIG/CMMC mapping

---

## v3.x — Retired

The v3 codebase is retained in the old repository for historical reference but is no longer maintained. All future development is in v4.

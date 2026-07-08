# Runbook — Getting a Clean NRG Collection (and comparing to ScubaGear)

**Use this when a run comes back with mass "Gap" findings, empty DNS, or `EXO: false` in the
results JSON `Connections` block.** The reference incident (a small customer tenant) is the pattern: Graph
object-shape mismatch + an EXO MSAL assembly conflict corrupted collection and produced false
gaps (a role collector even reported "0 Global Admins" when several existed).

---

## Step 0 — Confirm you have the problem

Open the results JSON and check two things:

```powershell
$r = Get-Content .\output\<tenant>\<timestamp>-results.json -Raw | ConvertFrom-Json
$r.Connections            # EXO/SharePoint/IPPSSession = false  →  connection failures
$r.Exceptions.Count       # >10 exceptions  →  collection is compromised
$r.Exceptions | Select -First 20
```

Two signatures to look for:
- `Could not load file or assembly 'Microsoft.Identity.Client.dll' ... manifest definition
  does not match` → **EXO MSAL assembly conflict** (Step 2).
- Many `The property '@odata.nextLink' cannot be found on this object` → **Graph object-shape
  mismatch under StrictMode** (Step 1). This is fixed permanently by the code wrapper (see the
  companion PR), but pinning the SDK avoids it today.

---

## Step 1 — Pin the Microsoft.Graph SDK to a known-good version

The tool's collectors were written against `Invoke-MgGraphRequest`'s **Hashtable** output
shape. Newer SDK builds can return PSCustomObject, which throws under `Set-StrictMode -Version
Latest` on absent properties. Pin to the 2.x line the manifest targets:

```powershell
# What you have now (likely multiple versions, newest winning):
Get-InstalledModule Microsoft.Graph* | Select Name, Version | Sort Name

# Remove drift and install the tested floor from the manifest (>= 2.20.0, < 3.0):
# (run elevated; close all other PowerShell first)
Get-InstalledModule Microsoft.Graph -AllVersions | Where Version -ge '3.0.0' |
    Uninstall-Module -Force -ErrorAction SilentlyContinue
Install-Module Microsoft.Graph -RequiredVersion 2.25.0 -Scope CurrentUser -Force
```

> The permanent fix (companion PR) forces `-OutputType Hashtable` inside the tool so the SDK
> version no longer matters. Until that ships, pinning is the reliable workaround.

---

## Step 2 — Fix the EXO / Graph assembly conflict (the reason EXO, Purview, DNS were empty)

`Microsoft.Graph` and `ExchangeOnlineManagement` each bundle a **different** version of
`Microsoft.Identity.Client.dll`. Loading both into one PowerShell session collides — the
second one to load fails. A conflicting EOM build (e.g. **3.10.0**) vs Graph's bundled MSAL is the trigger.

**Reliable fix — start from a clean session and load EOM in the right order:**

```powershell
# 1. Fresh pwsh 7 window (no leftover modules loaded)
pwsh -NoProfile

# 2. Pin a compatible EOM version and import it FIRST, before Graph pulls its MSAL in:
Install-Module ExchangeOnlineManagement -RequiredVersion 3.5.1 -Scope CurrentUser -Force
Import-Module ExchangeOnlineManagement

# 3. Then run the assessment (its Connect logic loads Graph after):
.\Invoke-NRGAssessment.ps1 -TenantDomain <customer-tenant> -DnsDomains <customer-tenant>
```

If the conflict persists on this workstation, the bulletproof isolation is to run
**EXO-dependent collection in a separate process** from Graph. That process-isolation is on the
tool roadmap; until then, the clean-session + version-pin above resolves it in practice.

---

## Step 3 — Always pass `-DnsDomains` explicitly

DNS came back empty because, with no `-DnsDomains`, the collector falls back to **EXO accepted
domains** — and EXO was dead. Public DNS records (SPF/DMARC/DNSSEC/MTA-STS) don't need EXO, so
always pass the domain(s) directly and they'll resolve even if EXO fails:

```powershell
.\Invoke-NRGAssessment.ps1 -TenantDomain <customer-tenant> -DnsDomains '<customer-tenant>'
# multiple: -DnsDomains '<customer-primary-domain>','<customer-secondary-domain>'
```

*(The companion PR also makes the collector fall back to Graph verified-domains, so DKIM is the
only check that still needs EXO.)*

---

## Step 4 — Validate the re-run BEFORE showing the client

```powershell
$r = Get-Content .\output\<customer-tenant>\<new>-results.json -Raw | ConvertFrom-Json
$r.Connections               # want: Graph/EXO/SharePoint all true
$r.Exceptions.Count          # want: 0, or only benign license/scope notes
($r.Findings | ? State -eq 'Gap').Count      # sanity-check against ScubaGear
($r.Findings | ? ControlId -like 'DNS-*')    # want: real SPF/DMARC values, not blank
```

Cross-check the Global Admin finding specifically — if it still says "0", collection is still
broken. ScubaGear enumerated them correctly.

---

## Step 5 — Run ScubaGear and compare (recurring QA)

ScubaGear is CISA's reference SCuBA tool — a great independent second opinion on the AAD / SPO /
Teams / PowerPlatform controls. It does **not** cover email-auth DNS, EXO, or Defender — that's
where NRG adds value beyond it.

```powershell
Install-Module ScubaGear -Scope CurrentUser
Invoke-SCuBA -ProductNames aad,sharepoint,teams,powerplatform -OPPath .\ScubaOutput
```

Then run the crosswalk (uses each NRG control's `References.SCuBA` field):

```powershell
# See tools/Compare-NRGToScubaGear.ps1 (companion PR) — joins NRG results.json against
# ScubaResults.json and reports AGREE / NRG-FALSE-GAP / NRG-MISSED per control.
```

**Interpretation guide:**
- **AGREE** → high confidence, action it.
- **NRG-FALSE-GAP** (NRG=Gap, Scuba=Pass) → NRG collection artifact; do not action, investigate the collector.
- **NRG-MISSED** (NRG=Pass, Scuba=Fail) → verify manually; ScubaGear usually right on AAD.
- **DNS / EXO / Defender** → NRG-only; ScubaGear has no opinion.

---

### Quick reference — the <customer-tenant> 2026-07-07 failure in one line

> Newer Graph SDK returned PSCustomObject → bare `$resp.'@odata.nextLink'` threw under
> StrictMode on a small (single-page) tenant → collectors bailed with empty data → evaluators
> scored empty as "Gap" → EXO MSAL conflict killed EXO/Purview/SharePoint/DNS on top. Fix the
> environment (Steps 1–3), re-run, validate (Step 4), then the ScubaGear crosswalk (Step 5)
> should show broad agreement.

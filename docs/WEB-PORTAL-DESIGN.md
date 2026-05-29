# Web Portal — Design Doc

**Status:** Design. No code yet. Companion to `docs/ROADMAP-v4.9.0.md`. The v4.9.0 roadmap defines new features for the PowerShell tool; this doc defines a parallel **product surface** — a multi-tenant web portal that lets customer admins consent once, then lets any user in that tenant view assessment results (RBAC-gated).

**Scope:** NRG-Assessment-Tool only. The sibling NLS-Assessment repo is the open-source CLI rebrand; a hosted SaaS portal is an NRG-commercial decision and is intentionally not mirrored.

**Author:** Matthew Levorson · NRG Technology Services / NextLayerSec LLC.

---

## Why this exists

The CLI tool delivers a beautiful report — but only the operator can run it, and only on their workstation. Customers ask between assessments: "what's our score now?", "is that gap fixed yet?", "can my IT person see the report without bothering you?". A self-service portal answers all three without changing the MSP delivery model.

**Business model preserved.** The portal does NOT replace the MSP engagement. It complements it:

- **MSP sells (unchanged):** interpretation, remediation, quarterly review, attestation walkthrough, executive briefing.
- **Portal provides (new):** standing access to current state, history view, "is this fixed?" verification, regression alerting.

Customers who would never pay for a "DIY scanner" still pay for the conversation. The portal is a **retention** tool, not a substitute for the consulting.

---

## The user model (explicit)

The model proposed by the operator:

> "Let's say I want sign-in — I use an admin account once, then next scans I can use a non-Global-Admin account, but the user can only see reports or what's being remediated."

Decoded:

1. **First contact (admin consent ceremony).** A tenant's Global Admin (or Privileged Role Admin) signs in. They grant **application permissions** to the NRG-Portal multi-tenant app. From that moment on, the **app itself** has tenant-wide read access via Microsoft Graph; subsequent users don't need to re-consent.
2. **Routine sign-in (any user, role-gated UI).** Anyone in the tenant can sign in via Entra. The portal reads their directory roles from the ID token, and the UI gates by role.
3. **No regular user ever triggers Graph calls directly.** All Graph traffic uses the app's application permissions. The signed-in user is identity + RBAC only.

This model is critical because **delegated** Graph permissions are constrained by the user's actual directory role. A regular user signing in delegated would get `403 Authorization_RequestDenied` on most assessment scopes. By using **application** permissions, the app holds the access; the user just signs in to identify themselves.

---

## RBAC matrix

The role check happens client-side on token claims AND server-side on every API call (defense in depth).

| Customer-tenant role | Dashboard | History | Trigger scan | Mark remediated | Tenant settings |
|---|---|---|---|---|---|
| Global Administrator | ✅ | ✅ | ✅ | ✅ | ✅ |
| Security Administrator | ✅ | ✅ | ✅ | ✅ | ❌ |
| Privileged Role Administrator | ✅ | ✅ | ✅ | ✅ | ❌ |
| Security Reader | ✅ | ✅ | ❌ | ❌ | ❌ |
| Compliance Administrator | ✅ | ✅ | ❌ | ✅ | ❌ |
| Member of `NRG-Portal-Users` group | ✅ | ✅ | ❌ | ❌ | ❌ |
| Any other authenticated user in tenant | "You do not have access to this portal — ask your Global Admin to add you to the NRG-Portal-Users group." | | | | |

**Server-side enforcement.** Every API endpoint validates the JWT, extracts the user's `roles` and `groups` claims, and refuses requests that don't satisfy the endpoint's permission set. Client-side hiding of buttons is UX, not security.

---

## Architecture

```
                  ┌──────────────────────────────────────────────────────┐
                  │  Browser (customer)                                   │
                  │  Svelte + Vite + strict CSP (sha256-pinned scripts)   │
                  └────────────────────────┬─────────────────────────────┘
                                           │ HTTPS, Bearer token
                  ┌────────────────────────▼─────────────────────────────┐
                  │  Azure Static Web Apps (free tier)                    │
                  │  - serves static frontend                             │
                  │  - built-in Entra ID auth                             │
                  │  - PR preview environments                            │
                  └────────────────────────┬─────────────────────────────┘
                                           │ /api/* proxy
                  ┌────────────────────────▼─────────────────────────────┐
                  │  Azure Container Apps  (scale to zero)                │
                  │  Container: Debian + Node 22 + pwsh 7.4               │
                  │                                                       │
                  │  Fastify API:                                         │
                  │    - JWT validation (multi-tenant audience check)     │
                  │    - RBAC middleware (claims → permission set)        │
                  │    - SSE endpoints for live scan progress             │
                  │                                                       │
                  │  Scan runner:                                         │
                  │    child_process.spawn('pwsh', ['-File',              │
                  │      './Invoke-NRGAssessment.ps1', '-TenantId', ...]) │
                  │    - stdout streamed via SSE to browser               │
                  │    - on completion: results uploaded to Blob,         │
                  │      metadata + index row to Cosmos                   │
                  └─────┬──────────────────────────────┬──────────────────┘
                        │                              │
        ┌───────────────▼──────────────┐   ┌──────────▼─────────────────┐
        │  Azure Blob Storage           │   │  Azure Cosmos DB (serverless)│
        │  /reports/{tid}/{runId}.json  │   │  Partition key: tenantId    │
        │  /reports/{tid}/{runId}.html  │   │  Containers:                │
        │  Per-tenant access policy via │   │   - runs (scan metadata)    │
        │  SAS tokens minted server-side│   │   - users (RBAC overrides)  │
        │  on demand.                   │   │   - audit (every action)    │
        └──────────────────────────────┘   └────────────────────────────┘

        ┌────────────────────────────────────────────────────────────────┐
        │  Azure Key Vault                                                │
        │  - App client secret (one cert per env: prod, staging)          │
        │  - Cosmos / Blob master keys                                    │
        │  - Container Apps pulls via managed identity (no app config)    │
        └────────────────────────────────────────────────────────────────┘
```

### Tech-stack table

| Layer | Tech | Why this and not the alternative |
|---|---|---|
| Frontend framework | Svelte 5 + Vite | Smaller bundles than React; native CSP support (no eval); built-in transitions for dashboard UX. React is the safer default if you want a bigger hiring pool. |
| Frontend hosting | Azure Static Web Apps | Free tier covers prod; built-in Entra auth; auto-renews TLS; PR preview environments are free QA gold. |
| Backend runtime | Node 22 LTS | Long-term support through 2027; native fetch; native test runner. |
| Backend framework | Fastify 5 | Better than Express for our case: built-in JSON schema validation on every route, ~4× throughput, native plugin model for the JWT + RBAC middleware. |
| Backend hosting | Azure Container Apps | Needed because pwsh subprocess + scan duration (5–15 min). Functions Consumption tops out at 10 min; Container Apps scale-to-zero is cheaper than Premium Functions. |
| Container base | `mcr.microsoft.com/azure-powershell:debian-bookworm-7.4` + Node added | Microsoft-maintained pwsh image; we add Node for the API layer. Single container is simpler than two-container compositions. |
| Scan invocation | `child_process.spawn('pwsh', [...])` | Reuses 100 % of existing NRG-Assessment module code with zero rewrites. The PS module already exports the entry point we need. |
| Real-time progress | Server-Sent Events | Simpler than WebSockets for one-way data; works through corporate proxies; survives connection drops. |
| Identity / auth | MSAL Node + MSAL Browser | Microsoft-supported libraries handle multi-tenant audience, refresh tokens, PKCE. Token validation uses `jwks-rsa` against Entra's metadata endpoint. |
| Reports + raw JSON | Azure Blob Storage | Cheap for the ~500 KB–2 MB JSON+HTML per scan. Per-tenant container with SAS-token access (issued server-side per request, ≤15 min lifetime). |
| Metadata + RBAC + audit | Azure Cosmos DB (serverless tier) | Partition key = tenantId means a single misconfigured query physically cannot return cross-tenant data. Serverless is pay-per-RU, cheap at our scale. |
| Secrets | Azure Key Vault | Container Apps managed identity → Key Vault. App config never holds secrets. |
| Logs / telemetry | Azure Monitor + Log Analytics workspace | Container Apps emits stdout/stderr; we tag every log with `tenantId` for per-tenant queries. |
| Custom domain | `portal.nrgtechservices.com` | Free TLS via Static Web Apps' Apex domain support. |

---

## Data model

### Cosmos DB containers

**`runs` container** — one document per scan run.

```json
{
  "id": "9c7b1d40-...-uuid",                  // also runId; doc id
  "tenantId": "11111111-2222-3333-4444-...",  // partition key
  "tenantName": "Frontier Precision",         // display
  "startedAt": "2026-05-28T14:22:11Z",
  "completedAt": "2026-05-28T14:33:09Z",
  "status": "Completed",                      // Queued|Running|Completed|Failed
  "triggeredBy": {
    "upn": "matt@frontierprecision.com",
    "displayName": "Matt Levorson",
    "directoryRoles": ["Global Administrator"]
  },
  "toolVersion": "4.6.7",
  "controlsEvaluated": 254,
  "summary": {
    "score": 42,
    "satisfied": 48, "partial": 47, "gap": 75, "notApplicable": 84
  },
  "blobPaths": {
    "json": "reports/{tenantId}/9c7b1d40-...-results.json",
    "html": "reports/{tenantId}/9c7b1d40-...-assessment.html"
  },
  "schemaVersion": 1
}
```

**`tenants` container** — one document per tenant onboarded.

```json
{
  "id": "11111111-2222-3333-4444-...",        // also partition key
  "tenantId": "11111111-2222-3333-4444-...",
  "primaryDomain": "frontierprecision.com",
  "displayName": "Frontier Precision",
  "consentedAt": "2026-05-28T14:00:00Z",
  "consentedBy": "matt@frontierprecision.com",
  "active": true,
  "settings": {
    "scanSchedule": "weekly",                  // weekly|monthly|onDemand
    "alertEmail": "it@frontierprecision.com"
  },
  "schemaVersion": 1
}
```

**`audit` container** — append-only log of every state-changing action.

```json
{
  "id": "log-event-uuid",
  "tenantId": "...",                          // partition key
  "occurredAt": "2026-05-28T14:22:11Z",
  "actor": { "upn": "...", "displayName": "..." },
  "action": "Scan.Triggered",                 // dotted-namespace
  "details": { "runId": "..." },
  "outcome": "Success",
  "sourceIp": "203.0.113.42",
  "userAgent": "Mozilla/5.0 ..."
}
```

Action namespace (initial set):

`Scan.Triggered` · `Scan.Completed` · `Scan.Failed` · `Tenant.Consented` · `Tenant.Disabled` · `Settings.Updated` · `User.PermissionDenied` · `Report.Downloaded` · `Finding.MarkedRemediated`

### Blob layout

```
container: reports
  /{tenantId}/{runId}-results.json   ← machine-readable
  /{tenantId}/{runId}-assessment.html ← shipped to operator browsers
  /{tenantId}/{runId}-playbook.md     ← engineer-facing remediation
  /{tenantId}/{runId}-executive.md    ← exec-facing
```

Storage account has **public access disabled**. The portal mints a short-lived SAS token (15-minute expiry, read-only) server-side after RBAC check; the SAS goes to the browser, the browser fetches direct from Blob. This keeps Container Apps out of the hot path for large downloads.

---

## API surface (REST)

Conventions: every endpoint requires a valid JWT in `Authorization: Bearer ...`. JWT must (a) have an audience matching our app reg client id, (b) be signed by Entra against the multi-tenant signing keys, (c) include `tid` (tenant ID) and `oid` (object ID) claims. Role checks happen after JWT validation.

| Method | Path | Permission | What it does |
|---|---|---|---|
| `GET` | `/api/me` | authenticated | Returns the current user's `upn`, `directoryRoles`, `groups`, computed `permissions` array for client-side UI hints. |
| `GET` | `/api/tenant` | authenticated, member of tenant | Returns the tenant's settings, consent state, last scan summary. |
| `GET` | `/api/runs?limit=N` | authenticated | List recent runs for the current tenant. Sorted newest-first. |
| `GET` | `/api/runs/:runId` | authenticated | Run metadata (score, summary). |
| `GET` | `/api/runs/:runId/report.html` | authenticated | Returns a redirect to a 15-min SAS URL for the HTML report blob. |
| `GET` | `/api/runs/:runId/report.json` | authenticated | Same, JSON blob. |
| `POST` | `/api/runs` | `Scan.Trigger` permission | Queues a new scan. Returns `runId`. |
| `GET` | `/api/runs/:runId/events` | authenticated | SSE stream of scan progress (`scanStarted`, `collectorStarted`, `collectorCompleted`, `evaluatorProgress`, `scanCompleted`, `scanFailed`). |
| `POST` | `/api/findings/:findingId/remediate` | `Finding.MarkRemediated` permission | Records a "we fixed this" marker for the next scan's delta view. |
| `PATCH` | `/api/tenant/settings` | `Tenant.Settings` permission | Update scan schedule, alert email. |
| `POST` | `/api/onboard` | unauthenticated, but admin-consent token required | First-time onboard. Tenant id from the admin's consent token. Creates the tenant document, triggers initial scan. |
| `GET` | `/api/audit?from=...&to=...` | `Audit.Read` permission | Returns the audit log for the tenant. |

Server-side permission mapping (centralized so it can be tested):

```ts
const Permissions = {
  'Global Administrator':        ['Scan.Trigger','Finding.MarkRemediated','Tenant.Settings','Audit.Read'],
  'Security Administrator':      ['Scan.Trigger','Finding.MarkRemediated','Audit.Read'],
  'Privileged Role Administrator':['Scan.Trigger','Finding.MarkRemediated','Audit.Read'],
  'Compliance Administrator':    ['Finding.MarkRemediated'],
  'Security Reader':             [],
  'NRG-Portal-Users (group)':    [],
}
```

Permission checks compose; if the user holds two roles, their permission set is the union.

---

## Auth flows

### First-time onboarding (admin consent)

```
1. Admin browses to portal.nrgtechservices.com
2. UI says "Connect your Microsoft 365 tenant" → "Start"
3. Browser → Microsoft Entra `/adminconsent` endpoint:
     ?client_id={nrgPortalClientId}
     &scope=https://graph.microsoft.com/.default
     &redirect_uri=https://portal.nrgtechservices.com/onboarded
     &state={csrfNonce}
4. Admin signs in to Entra (with their tenant credentials).
5. Entra shows the consent dialog listing every application permission the app requests.
6. Admin clicks Accept → Entra redirects back with ?tenant={tid}&state={csrfNonce}&admin_consent=True
7. Portal verifies state, looks up tenant via Graph (using the app's now-granted permissions),
   creates `tenants` doc in Cosmos, kicks off initial scan, redirects to dashboard.
```

The admin's Entra session is discarded after the consent; the portal does not store the admin's identity beyond the audit log entry. The app's own service principal is what holds the access from here on.

### Subsequent sign-in (any user)

```
1. User clicks "Sign in with Microsoft" → MSAL Browser PKCE flow.
2. User authenticates with Entra (their normal sign-in).
3. Entra returns an ID token + access token for our API audience.
4. Browser stores tokens in memory (NOT localStorage; refresh via silent flow).
5. Browser calls /api/me with the access token.
6. Backend validates the token, extracts directoryRoles + groups, computes permissions, returns to UI.
7. UI shows / hides controls based on the permissions array.
```

If the user's tenant has not yet completed admin consent, `/api/me` returns `403 TenantNotOnboarded` with the onboarding URL — the user sees "Ask your Global Admin to complete onboarding" and a copy-paste link to send their admin.

---

## Security model

### Tenant isolation

**Cosmos DB** — partition key is always `tenantId`. Every query the backend issues includes a `WHERE c.tenantId = @tid` clause AND the partition key for the read. Cross-tenant data physically cannot be returned by a correctly-constructed query.

**Blob** — every blob path begins with `/{tenantId}/`. SAS tokens issued by the backend are scoped to a single blob path. A user authenticated to tenant A cannot get a SAS for a blob in tenant B.

**JWT** — every API call validates that the JWT's `tid` claim matches the tenant being operated on. Server middleware refuses any request where they diverge.

These three controls are independent — defeating tenant isolation would require all three to fail simultaneously.

### CSP (continues the in-tool standard)

Static Web Apps configuration emits:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'sha256-{frontendBundleHash}' https://login.microsoftonline.com;
  style-src 'self' 'unsafe-inline';
  connect-src 'self' https://graph.microsoft.com https://login.microsoftonline.com
              https://{cosmosAccount}.documents.azure.com https://{blobAccount}.blob.core.windows.net;
  img-src 'self' data: https:;
  font-src 'self';
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  require-trusted-types-for 'script';
```

Same Trusted Types model as the existing report HTML. The frontend bundle hash is baked into the CSP at build time by the same kind of self-check we shipped for the HTML publisher.

### Token handling

- **Access tokens** live in JavaScript memory only. Never localStorage, never sessionStorage. (Survives reload via MSAL silent refresh against Entra.)
- **Refresh tokens** stay in MSAL Browser's in-memory cache.
- Backend **never** sees the user's tokens — it only validates the access token presented on each request.
- The app's own client credential (cert preferred over secret) lives in Key Vault; Container Apps loads via managed identity at startup.

### Threat model (initial)

| Threat | Mitigation |
|---|---|
| Compromised customer admin account | Limited to that tenant's data; app cert is per-environment, not per-tenant; no cross-tenant impact. |
| Compromised portal application credential | All tenants exposed (read-only). Mitigations: cert (not secret), rotated quarterly, stored in Key Vault, alert on cert use from unexpected IP, ability to global-revoke via Entra admin portal. |
| XSS in the portal | CSP, Trusted Types, framework-level escaping (Svelte auto-escapes), no `{@html}` directives anywhere. |
| Replay of a stale token | Tokens are short-lived (~1 hour); refresh requires re-auth against Entra. |
| Cross-tenant data leak via query bug | Three-layer isolation (above); RBAC tests on every endpoint; integration tests run a two-tenant scenario and assert zero cross-talk. |
| Long-running scan exhausts container | Scan duration capped (default 30 min); Container Apps min-replica scale; queue backpressure prevents starvation. |
| DoS via repeated scan triggers | Per-tenant rate limit (max one running scan + one queued); per-user rate limit (max 10/hour). |
| Operator (NRG) compromised | The app's cert is the keys to every customer's data. Treat like any other long-lived credential: rotate, monitor, runbook. (Existing `docs/INCIDENT-RESPONSE.md` Scenario 2 already covers this.) |

### Compliance posture

- **Data residency.** Pin all storage to a single Azure region (e.g. East US 2). Document in the privacy policy.
- **DPA template.** One-page Data Processing Agreement; "we hold tenant configuration data, scope-limited to read-only Graph reads, retained for X months, exported on request, deleted on tenant disable."
- **Customer-data export.** `POST /api/tenant/export` returns a zip of all scan JSON + audit log for the tenant.
- **Customer-data delete.** `POST /api/tenant/disable` purges the tenant's Blob container, removes Cosmos partition data, revokes the app's consent record. 30-day grace period before purge (retrievable).

---

## Cost model

Monthly estimates, USD, assuming 20 active tenants and one scan per tenant per week (~80 scans/mo, each ~10 min compute).

| Resource | SKU | Estimate |
|---|---|---|
| Azure Static Web Apps | Free tier | $0 |
| Azure Container Apps | Consumption, scale-to-zero | $5–15 (compute-seconds only when scanning) |
| Azure Cosmos DB | Serverless | $5–15 (RU/s pay-per-use; reads dominate) |
| Azure Blob Storage | Hot tier, ~50 GB | <$2 |
| Azure Key Vault | Standard | <$1 |
| Azure Monitor + Log Analytics | Pay-as-you-go (~1 GB ingest/mo) | $3–5 |
| Custom domain + TLS | Built-in | $0 |
| Entra ID (sign-in only) | Free tier | $0 |
| **Total** | | **$15–40/mo at MVP scale** |

Scales roughly linearly with tenant count up to ~100 tenants; past that, move Cosmos to provisioned throughput and Container Apps to dedicated for cost predictability.

---

## MVP scope (v1.0)

### In

- Multi-tenant Entra app reg with admin consent flow.
- One-time admin onboarding ceremony.
- Routine sign-in for any user (any role); permissions computed from directory roles.
- Trigger scan (admin path only); reuses existing `Invoke-NRGAssessment.ps1` via pwsh subprocess.
- Live scan progress via SSE.
- Dashboard view: score, gaps by severity, latest scan timestamp.
- History view: list of past runs, drill-in to report.
- Report viewer: same HTML report content as today, served from Blob.
- Per-tenant data isolation (Cosmos partition key + Blob path scoping).
- Audit log of every state-changing action.
- Static Web Apps + Container Apps + Cosmos + Blob + Key Vault provisioned via Bicep.

### Deferred to v2

- Remediation workflow: mark gap as fixed, track over time, regression detection.
- Multi-client portfolio view (the existing v4.9.0 F13 feature, but for the web).
- Webhook / email alerts on regression.
- Custom branding per customer.
- Stripe / Azure Marketplace billing.
- SOC 2 audit-ready logging.
- IG1/IG2 scoring tiles (depends on v4.9.0 F11 schema migration landing first in the CLI).
- Attestation form integration (depends on v4.9.0 F12).
- Maester rule integration (depends on v4.9.0 F14 outcome).

### Out of scope (will not build in this product)

- An endpoint posture scanner. That belongs in a separate companion tool.
- A SIEM / log analytics surface. Existing Sentinel / equivalent is the right home.
- A ticketing system. Integrate with ConnectWise / HaloPSA, don't replace.

---

## Repository structure

A new repo `nrg-portal` (separate from `NRG-Assessment-Tool`) keeps concerns clean. The portal **consumes** the CLI tool as a git submodule pinned to a known release tag. CLI updates land in `NRG-Assessment-Tool`; the portal bumps its submodule pointer deliberately.

```
nrg-portal/
├── README.md
├── SECURITY.md
├── docs/
│   ├── ARCHITECTURE.md           ← this doc, copied + maintained here
│   ├── ONBOARDING-CUSTOMER.md    ← admin-facing onboarding guide
│   └── OPERATIONS.md             ← MSP-internal ops runbook
├── infra/
│   ├── main.bicep                ← Azure resource graph (Static Web Apps,
│   │                               Container Apps, Cosmos, Blob, Key Vault)
│   ├── parameters.prod.json
│   └── parameters.staging.json
├── api/                          ← backend
│   ├── src/
│   │   ├── server.ts             ← Fastify entrypoint
│   │   ├── auth/jwt.ts
│   │   ├── auth/rbac.ts
│   │   ├── routes/
│   │   │   ├── me.ts
│   │   │   ├── tenant.ts
│   │   │   ├── runs.ts
│   │   │   └── audit.ts
│   │   ├── scan/runner.ts        ← spawn pwsh, stream stdout
│   │   ├── scan/sse.ts
│   │   ├── data/cosmos.ts
│   │   └── data/blob.ts
│   ├── test/                     ← Node test runner; two-tenant isolation
│   │                               scenario MUST pass
│   ├── Dockerfile                ← pwsh + Node base
│   └── package.json
├── web/                          ← frontend
│   ├── src/
│   │   ├── App.svelte
│   │   ├── routes/
│   │   ├── lib/auth.ts           ← MSAL Browser wrapper
│   │   └── lib/api.ts
│   ├── public/
│   ├── svelte.config.js
│   ├── vite.config.ts
│   └── package.json
├── nrg-assessment-tool/          ← submodule pinned to a release tag
└── .github/
    ├── workflows/
    │   ├── ci.yml                ← lint, type-check, tests (mirrors CLI repo style)
    │   ├── codeql.yml
    │   ├── dependency-review.yml
    │   ├── scorecard.yml
    │   ├── secret-scan.yml       ← gitleaks + trufflehog (same as CLI repo)
    │   └── deploy.yml            ← on tag: build + push image + bicep deploy
    └── dependabot.yml            ← github-actions + npm
```

---

## Operational requirements (before v1.0 ships)

1. **Entra app registration.** Multi-tenant, application permissions for: `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `SecurityEvents.Read.All`, `Reports.Read.All`, `Group.Read.All`, `Application.Read.All`, `RoleManagement.Read.All`, `User.Read.All`, `IdentityRiskyUser.Read.All`. Cert credential (not secret); 90-day rotation.
2. **Azure subscription with budget alert at $50/mo.** Prevents runaway billing surprises.
3. **Resource group `nrg-portal-prod`** (and `nrg-portal-staging` for the PR-preview backend).
4. **Custom domain `portal.nrgtechservices.com`** — CNAME to Static Web Apps default URL.
5. **Privacy policy + DPA template** published at `nrgtechservices.com/legal`.
6. **Status page** (Azure Status hosted or third-party like Statuspage). Customers expect one once you're a SaaS.
7. **Branch protection on `nrg-portal/main`** — same posture as the CLI repos: require PR, status checks, signed commits, no force-push.
8. **Monitoring dashboard in Azure Monitor** — scan success rate, p50/p95 scan duration, error rate by tenant, Cosmos RU consumption.

---

## Open questions

| # | Question | Default if not answered |
|---|---|---|
| 1 | What additional Graph scopes are needed for the Defender / Purview / Intune collectors? Inventory before app reg, since adding scopes later requires every customer to re-consent. | Land MVP with the AAD/EXO/DNS subset; defer the rest to a v1.1 with scheduled re-consent campaign. |
| 2 | Does the CLI's existing `Invoke-NRGAssessment.ps1` accept an application-permission token, or only interactive sign-in? | Audit at scaffolding time; may need a thin auth-adapter layer in the portal that minted an EXO token from the app cert via `New-MgUserAccessToken` equivalent. |
| 3 | Cosmos serverless caps at 1 TB; what's the per-tenant data growth assumption? | ~10 MB per scan × ~50 scans/yr × 100 tenants = 50 GB/yr. Comfortably under serverless cap for years. |
| 4 | Scan parallelism. One scan at a time per tenant, or allow concurrent scans across tenants? | Concurrent across tenants (one per Container App replica); serial within a tenant (queue). |
| 5 | How does the portal handle a tenant whose Global Admin who consented later leaves the company? | The app's consent stays valid until explicitly revoked in Entra. Document this in the customer-facing onboarding guide; add a quarterly "still authorized?" email. |
| 6 | Customer-data export format. ZIP of JSON + HTML, or something richer? | ZIP of JSON + HTML + audit-log CSV. Sufficient for SOC 2 audit; future SQL/PowerBI export is post-MVP. |
| 7 | Where does the portal source the customer's IT contact (for alerts)? Hard-coded by admin during onboarding, or pulled from Graph? | Pulled from Graph at onboarding (`/me/manager` or the tenant's Technical Contact); overridable in settings. |
| 8 | What happens when a customer downgrades from an M365 tier that licensed the controls we evaluate? | License-aware scoring (already implemented in the CLI) handles this; the portal surfaces "controls no longer scored because license downgraded" in the dashboard. |

---

## Implementation order (post-design)

Each row is its own PR against `nrg-portal`. Numbers correspond to the deliverable, not effort.

| Wave | What lands | Why this order |
|---|---|---|
| 0 | Infra Bicep + CI scaffolding + empty Container App returning "hello world" | Prove the deployment story before building features. |
| 1 | Multi-tenant Entra sign-in (frontend + backend JWT validation) | Auth is the load-bearing first feature; without it, nothing else is testable. |
| 2 | RBAC middleware + `/api/me` returning permissions | Every later endpoint depends on this; lands before the endpoints. |
| 3 | Admin consent flow + `/api/onboard` + tenant document creation | Enables real-customer testing. |
| 4 | Cosmos data layer + audit log | Foundational; every action writes audit. |
| 5 | Scan runner (spawn pwsh, parse output, write Blob + Cosmos) | Self-contained backend; testable against the operator's own tenant first. |
| 6 | SSE progress stream | Wires the runner to the (still-empty) frontend. |
| 7 | Frontend dashboard + history + report viewer | First end-to-end user-visible feature. |
| 8 | Tenant settings + scheduled scans | Recurring revenue feature. |
| 9 | Export + delete (compliance) | Pre-launch checklist requirement. |
| 10 | Status page + monitoring dashboards | Required for "we're a SaaS" credibility. |

---

## Acceptance criteria for v1.0 ship

The portal is considered ready for first paying customer when:

- Two distinct test tenants have completed admin onboarding without operator intervention.
- A user from tenant A signing in cannot enumerate, read, or query any tenant-B data via any API endpoint (verified by integration test).
- A non-admin user from a tenant can sign in, see the dashboard, but receives 403 on every state-changing endpoint.
- A scan triggered from the portal produces a report whose top-line score matches a CLI-triggered scan of the same tenant ±2 %.
- Average scan duration < 10 min for a 250-control tenant.
- The portal survives a Container Apps replica restart mid-scan without data loss (scan resumes or fails cleanly with a retry button).
- CI pipeline matches the CLI repo's posture: PSScriptAnalyzer/equivalent, Pester/equivalent unit tests, CodeQL, Dependency Review, Scorecard, Gitleaks, TruffleHog, SBOM on tag.
- `docs/INCIDENT-RESPONSE.md` (the CLI's runbook) gains a "Portal compromise" scenario.
- Privacy policy + DPA published.
- A 30-day pen-test window has closed with no critical findings open.

---

*Design owner: Matthew Levorson — NRG Technology Services / NextLayerSec LLC. Next step (per the design conversation): scaffold the `nrg-portal` repo with Wave 0 + Wave 1, in a separate session.*

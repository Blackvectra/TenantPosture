# Incident Response Runbook

If you're reading this in a real incident: work the section top-to-bottom, do not skip steps to save time. Order matters.

## First 5 minutes (any incident)

1. Open this file from a clean device (phone, second laptop). The suspect machine can tamper with anything it can reach.
2. Start a paper or notes-app log: `HH:MM | what I did | what I observed`. You will need this for the post-mortem and any contractual / legal disclosure.
3. Decide which scenarios apply. Multiple can fire at once.

---

## Scenario 1 — GitHub credentials compromised

**Triggers:** PAT use you didn't initiate; unfamiliar SSH key in your account; code on `main` you didn't push; GitHub "your password was changed" email.

**Contain (5 min):**
1. https://github.com/settings/security → **Sign out everywhere**.
2. https://github.com/settings/tokens → revoke every classic and fine-grained PAT.
3. https://github.com/settings/keys → delete every SSH and GPG key.
4. https://github.com/settings/apps/authorizations → revoke every OAuth app.
5. Change GitHub password (fresh strong unique value).
6. Re-enroll 2FA with a hardware key if you weren't using one.

**Investigate:**
- https://github.com/settings/security-log — flag any IP/location/UA you don't recognize.
- For each repo: Settings → Collaborators — verify the list.
- Org-level audit log: https://github.com/organizations/Blackvectra/settings/audit-log

**Eradicate:**
- Force-push a known-good commit over anything malicious on `main` (only from a verified clean local checkout).
- `git push --delete origin <tag>` any release tag you can't verify; re-cut from a known-good SHA.
- Every value in repo Settings → Secrets is leaked. Rotate every one.

---

## Scenario 2 — M365 enterprise app secret / cert leaked

This is the highest-blast-radius asset for this tool. The app reads Graph on every client tenant that consented. Treat as a multi-customer breach until proven otherwise.

**Contain (15 min):**
1. https://entra.microsoft.com → App registrations → your app → Certificates & secrets.
2. **Delete the leaked secret/cert first.** Do not just add a new one — the old one stays valid until deleted.
3. If cert-based: revoke at the CA too.

**Detect spread (per client tenant):**
- Entra → Sign-in logs → Application = your app → window the last 30 days.
- Flag unexpected source IPs, after-hours activity, unusual call volume.
- The customer tenant's logs are the source of truth — your tenant only sees auth originating there.

**Eradicate:**
- Generate fresh secret/cert. Store in 1Password or Azure Key Vault — never in git, never in a workflow file, never in `clients.json`.
- `git log -p -- '*.json' '*.psd1' '*.ps1'` and grep for the leaked value. If it appears anywhere in history, run `git filter-repo` to scrub and force-push.

**Customer notification:**
- If audit logs show unexpected use against a client tenant, notify them within your contract's breach window (commonly 24–72h).
- Tell them: time window, source IPs, what data the app could read. For TenantPosture that's tenant config, user list, sampled mailbox audit config — no message bodies, no files.

**Recover:**
- Rotate this secret on a 90-day calendar reminder.
- Move to certificate-based auth if not already (cert > shared secret).

---

## Scenario 3 — Malicious dependency / compromised GitHub Action

**Triggers:** Dependabot alert, OSSF Scorecard score drop, CodeQL flag, unexpected CI behavior, action repo gets archived or transferred.

**Contain (30 min):**
1. https://github.com/Blackvectra/TenantPosture/actions → identify the workflow that uses the bad action → "…" → **Disable workflow**.
2. If the malicious step already ran: every secret referenced in that workflow is leaked. Cross-trigger Scenario 1 or 2 as applicable.

**Eradicate (GitHub Action case):**
- Re-pin the action to a known-good SHA on an earlier release. Push a single commit just for the pin.
- When bumping to a new SHA, verify by reading the diff between the old SHA and the new SHA, plus the maintainer's recent activity.
- If the maintainer is the suspect, switch to a fork or replace the action entirely.

**Eradicate (PSGallery module case — Microsoft.Graph, ExchangeOnlineManagement, Pester, PSScriptAnalyzer):**
1. On every workstation that ran the bad version: `Uninstall-PSResource -Name <Name> -Version <Bad>`.
2. Pin to a verified earlier version in `TenantPosture.psd1` and `.github/workflows/ci.yml`.
3. Re-run an assessment against a known-good tenant; diff the JSON against a prior snapshot to confirm clean output.

---

## Scenario 4 — In-house code-signing cert compromised

The cert sits in `Cert:\CurrentUser\My` on operator workstations and is referenced by `Sign-Release.ps1`. Loss of the private key lets an attacker sign malicious PS1s that pass `Test-TPSignatureStatus`.

**Contain (30 min) — on every operator workstation that had the cert:**
```powershell
$tp = (Get-Content "$env:USERPROFILE\.tp-assessment\signing-thumbprint.txt").Trim()
foreach ($store in @('My','Root','TrustedPublisher')) {
    Get-ChildItem -Path "Cert:\CurrentUser\$store\$tp" -ErrorAction SilentlyContinue | Remove-Item
}
Remove-Item -LiteralPath "$env:USERPROFILE\.tp-assessment\signing-thumbprint.txt" -ErrorAction SilentlyContinue
```

**Eradicate:**
- Yank every GitHub Release signed with the old cert (delete the release; keep the tag for forensics).
- Add a `SECURITY ADVISORY` block to README pinning the issue + old thumbprint.
- Generate a fresh cert: `.\Build\New-TPCodeSigningCert.ps1 -SaveThumbprintForBuild`.
- Re-sign current main from the fresh cert; cut a new release.

**Notify:**
- Anyone who received an artifact signed with the old cert. Give them old + new thumbprints so they can tell which.

**Recover:**
- Consider moving to Microsoft Trusted Signing (paid) — fewer "which self-signed cert is real?" questions.
- Document who has the private key and where it's stored.

---

## Scenario 5 — Active compromise discovered during an assessment

You run an assessment against a customer and the report shows red findings consistent with active compromise: new admin role assignments in last 24h, unfamiliar enterprise apps with high-privilege consent, simultaneous external forwarding on multiple mailboxes, new global admin accounts.

**Do not:**
- Do not immediately remediate. The attacker may notice and burn additional persistence.
- Do not notify on a channel the attacker might already be reading (the customer's email, Teams, SharePoint).

**Do:**
1. Call the customer's IT or security lead **by phone**.
2. Preserve evidence — archive the assessment JSON to a separate location. Pull the audit log range manually:
   ```powershell
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
     -ResultSize 5000 `
     -Operations New-RoleAssignment,Add-MailboxPermission,New-InboxRule,Consent
   ```
3. Engage the customer's IR provider (or yours if you're it). For Microsoft tenants on E5, Microsoft Detection & Response Team is reachable through Premier/Unified support.

---

## Post-incident (any scenario)

Within 7 days, write a short post-mortem at `docs/postmortems/YYYY-MM-DD-<summary>.md`:
- **Timeline:** detection → containment → eradication → recovery.
- **What worked / what didn't** about this runbook.
- **The one permanent control to add:** what would have prevented this or caught it sooner?
- **What got rotated:** every secret, cert, key, token.

Update this runbook with anything you learned. The next incident will not be identical, but the structure should still apply.

---

## Cheat sheet — who to call

| Compromise type | First call |
|---|---|
| GitHub credentials | https://support.github.com → "Account & Profile" |
| M365 enterprise app | Microsoft 365 admin → P1 ticket |
| Tenant compromise (customer) | Customer IT/security lead BY PHONE → Microsoft DART if contracted |
| In-house signing cert | No external party; internal-only mitigation |
| Malicious upstream dep | Report-a-vulnerability on the upstream repo; GitHub Advisory DB if novel |

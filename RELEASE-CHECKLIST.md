# Release Checklist — TenantPosture

Every patch release follows this checklist. It exists so that "security + bugs + polish, every release" is a verifiable contract instead of an aspiration.

## Pre-release — security pass

Run on the branch before merging the release PR.

- [ ] **OWASP Top 10:2021 delta walk.** Re-read `docs/CORRECTNESS-SWEEP-v4.6.5.md` § OWASP. For each of A01–A10, note in the CHANGELOG entry whether the new release changed the posture (better / same / new gap opened). Don't ship a release that *worsens* any category without an explicit note.
- [ ] **`simplify` skill code-review pass** on the PR diff. Apply confirmed findings; document refuted findings + intentional skips in the PR body.
- [ ] **Publisher output safety.** `Invoke-Pester ./Testing/TP.HtmlReport.Tests.ps1 ./Testing/TP.GoldenFixtures.Tests.ps1` passes. Confirms no new HTML / MD / PS injection vectors in the diff. (A dedicated adversarial-fixture suite, `TP.PublisherSafety.Tests.ps1`, is not yet written.)
- [ ] **All standing CI green:** PSScriptAnalyzer, Pester Tests, Module Manifest + controls.json. Optional Copilot reviewer comments triaged.
- [ ] **One real-tenant run** against an internal tenant. Confirm:
  - Zero `WARNING: Evaluator ... cannot be found on this object`
  - Zero `WARNING: <Publisher> publish failed`
  - Zero `WARNING: There are more results available ...`
  - Total Controls = Satisfied + Partial + Gap + NotApplicable (no silently-dropped findings)
  - XLSX + HTML playbook both generate

## Pre-release — bugs pass

- [ ] **Open entries in CORRECTNESS-SWEEP** updated. Anything resolved gets moved out of Open into Resolved. Anything still Open gets WONTFIX rationale or is bumped to next release.
- [ ] **No regression vs prior release.** Diff finding counts on a fixture tenant against the prior tag — total + Critical + High should not decrease (decreasing = silently dropping findings) or increase unexpectedly (= over-emission).

## Pre-release — polish pass

- [ ] **5 polish items shipped** per `docs/ROADMAP-v4.6.x-polish.md` (one section per patch release).
- [ ] **CHANGELOG.md entry** complete, with one bullet per shipped item and one explicit OWASP-delta note.
- [ ] **Version bump consistent** across psd1 ModuleVersion, CLAUDE.md header, README footer, SECURITY.md footer, psm1 fallback constant. Use `grep -rn "v4\.6\.<previous>"` to confirm.
- [ ] **CLAUDE.md updated** if architecture / public CLI / schema changed (no drift past 10 commits).

## Release — sign + tag

For the in-house workflow (free, self-signed). For an external release with a paid cert (Microsoft Trusted Signing / Sectigo / DigiCert), substitute the cert thumbprint in step 2.

**One-time per workstation** (skip if you've done it before):
```powershell
.\Build\New-TPCodeSigningCert.ps1 -SaveThumbprintForBuild
# Generates a self-signed cert, adds it to TrustedPublisher + Root,
# and stashes the thumbprint at ~/.tp-assessment/signing-thumbprint.txt
```

**Once per signing certificate** (repository settings → Variables): set
`TP_SIGNING_THUMBPRINT` to the certificate's SHA-1 thumbprint (printed by
`New-TPCodeSigningCert.ps1`). A hosted runner trusts no self-signed root, so the
release workflow accepts an untrusted signature only from that pinned signer;
rotate the variable when the certificate is renewed. Set `TP_REQUIRE_SIGNED`
to `true` once every release is signed and committed before tagging; it then also
requires the signed catalog (`TenantPosture.cat`) in the tagged commit, which is what
covers the shipped JavaScript, HTML and configuration no script signature reaches.

**Per release:**
```powershell
# 1. Start from a clean tracked tree. Sign-Release.ps1 refuses to run while a
#    tracked file differs from the index: the manifests hash the working tree
#    and the sign commit carries only the signed scripts and the manifests, so
#    a locally populated Config/clients.json would be hashed into a manifest
#    the tagged commit can never satisfy.
git status --porcelain                           # expect nothing but the files signing writes
git stash push -- Config/clients.json            # if it is populated locally
# Only tracked files are signed and hashed: an untracked or ignored script
# (a local secrets.ps1, a scratch file) is left alone and never enters a manifest.

# 2. Sign every .ps1/.psm1/.psd1 (writes tools/integrity-manifest.txt and
#    FILES.sha256 when present from the signed bytes, then builds and signs
#    the catalog from one export of the tracked tree)
.\Build\Sign-Release.ps1            # auto-loads the saved thumbprint

# 3. Verify signatures cleanly resolved
.\tools\Verify-Integrity.ps1        # exits 0 if all manifest entries match
.\Build\Sign-Release.ps1 -VerifyCatalogOnly -CertificateThumbprint <thumbprint>   # the catalog's signature, then its hashes over the tracked tree

# 4. Stage ONLY what signing changed, then commit, tag and push. The release
#    workflow checks the commit the tag points at, not your working tree:
#    unsigned committed scripts make an unsigned release (or a failed one
#    under TP_REQUIRE_SIGNED). Never `git add -A` here: on an operator
#    workstation Config/clients.json and other local edits are tracked files
#    and would ride into the release commit and its archive.
git add -u -- '*.ps1' '*.psm1' '*.psd1' '*.ps1xml'
git add -- tools/integrity-manifest.txt TenantPosture.cat
git status --short                  # expect signed scripts, the manifest and the catalog; nothing else
git commit -m "Sign vX.Y.Z"
git tag -s "vX.Y.Z" -m "vX.Y.Z — release notes here"
git push origin main "vX.Y.Z"      # the signing commit AND the tag: a tag alone leaves main unsigned
```

Sign-Release.ps1 writes the signed scripts in the repository's committed form (LF; git
normalizes CRLF on commit and would otherwise rewrite the signature block after the manifests
were computed) and re-reads each signature on those bytes, so the manifests describe the bytes
that are committed. Restore the stashed `Config/clients.json` after the tag is pushed.

If the operator workstation doesn't have the cert (e.g., a different engineer is releasing), run `New-TPCodeSigningCert.ps1` first. The signature won't verify on workstations that don't trust the cert — that's the point. For internal-only releases, install the cert into TrustedPublisher on every workstation that runs the tool.

## Post-release

- [ ] **GitHub Release** created from the tag with the CHANGELOG entry as the body.
- [ ] **SBOM** (`tools/Generate-SBOM.ps1`) attached to the release artifact.
- [ ] **Integrity manifest** (`tools/integrity-manifest.txt`) attached too.
- [ ] **Real-tenant smoke** run on the released tag (not the branch) one final time before announcing internally.

## When the contract breaks

If a release ships without going through this checklist:
- Document **why** in the next release's CHANGELOG.
- Schedule a follow-up patch within 30 days that brings the skipped item back into compliance.

The point isn't that every step is perfect every time — it's that skipped steps are *visible* in the audit trail and don't quietly compound.

---

*Owner: NRG Technology Services / NextLayerSec LLC. Updated whenever the release process changes.*

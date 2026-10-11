# Releasing TenantPosture

How to cut a release. The release pipeline (`.github/workflows/release.yml`)
fires **only on tags matching `v*`** — e.g. `v4.13.0`. Tags without the `v`
prefix (like the early `4.12.0`-style tags on the NLS repo) never trigger it,
which is why historical releases shipped without SBOM/integrity verification
or checksummed assets.

## Checklist

1. **Land everything on `main`.** All release content merges via PR with CI
   green (full Pester suite, PSScriptAnalyzer, schema validation, secret scan).

2. **Update the version trio in one commit:**
   - `TenantPosture.psd1` → `ModuleVersion`
   - `CLAUDE.md` header → `**Version:**`
   - `CHANGELOG.md` → move `## Unreleased` content under the new
     `## vX.Y.Z (YYYY-MM-DD)` heading

3. **Sign, then commit, then tag.** The release workflow checks the commit the
   tag points at, never a working tree, so a signed release means the signed
   files are committed before the tag exists. For an unsigned release skip the
   first two commands; the release notes will say "Unsigned release".

   ```powershell
   .\Build\Sign-Release.ps1            # signs, refreshes the manifests, builds the catalog
   git add -A && git commit -m "Sign vX.Y.Z"
   git tag -a vX.Y.Z -m "vX.Y.Z"      # must equal the manifest's ModuleVersion
   git push origin main vX.Y.Z
   ```

   Repository variables: `TP_SIGNING_THUMBPRINT` (the self-signed cert's SHA-1
   thumbprint; a hosted runner trusts no self-signed root, so only that pinned
   signer is accepted) and, once every release is signed, `TP_REQUIRE_SIGNED`
   = `true` to fail the pipeline on any unsigned script.

4. **The pipeline runs automatically:**
   | Job | Does |
   |---|---|
   | `sbom` | Generates the CycloneDX SBOM from the manifest's required modules |
   | `authenticode` | Verifies a committed integrity manifest and the Authenticode status of the shipped scripts (fails on tamper signals; unsigned is reported, or fails under `TP_REQUIRE_SIGNED`) |
   | `package` | Builds `TenantPosture-vX.Y.Z.zip` from the shipped-folder allowlist with `FILES.sha256` inside, writes `SHA256SUMS`, attests the archive, checksums and SBOM, and creates a **draft** GitHub Release (through the `release` environment) whose notes state the signing result |

5. **Review the draft release** on GitHub — check the generated notes
   (categories come from `.github/release.yml` labels), then **Publish**.

## Client verification

Ship the `SHA256SUMS` line with any zip you hand to a client:

```powershell
(Get-FileHash .\TenantPosture-v4.13.0.zip -Algorithm SHA256).Hash
# must match the value in SHA256SUMS
```

## Rules

- Tags are immutable once published — never move or delete a released tag
  (enforce with a tag ruleset: Settings → Rules → New tag ruleset →
  target `v*` → block deletion + non-fast-forward).
- Version bumps to the pinned dependency ranges in the manifest
  (`Microsoft.Graph.Authentication` < 3.0, `ExchangeOnlineManagement` < 4.0)
  are their own PR with a full-suite run — never part of a release commit.

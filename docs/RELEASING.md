# Releasing NRG-Assessment

How to cut a release. The release pipeline (`.github/workflows/release.yml`)
fires **only on tags matching `v*`** — e.g. `v4.13.0`. Tags without the `v`
prefix (like the early `4.12.0`-style tags on the NLS repo) never trigger it,
which is why historical releases shipped without SBOM/integrity verification
or checksummed assets.

## Checklist

1. **Land everything on `main`.** All release content merges via PR with CI
   green (full Pester suite, PSScriptAnalyzer, schema validation, secret scan).

2. **Update the version trio in one commit:**
   - `NRG-Assessment.psd1` → `ModuleVersion`
   - `CLAUDE.md` header → `**Version:**`
   - `CHANGELOG.md` → move `## Unreleased` content under the new
     `## vX.Y.Z (YYYY-MM-DD)` heading

3. **Tag and push** (annotated tag, `v` prefix — required):

   ```powershell
   git tag -a v4.13.0 -m "v4.13.0"
   git push origin v4.13.0
   ```

4. **The pipeline runs automatically:**
   | Job | Does |
   |---|---|
   | `sbom` | Generates the CycloneDX SBOM |
   | `authenticode` | Verifies integrity manifest + Authenticode status (fails on tamper signals) |
   | `package` | Builds `NRG-Assessment-vX.Y.Z.zip`, writes `SHA256SUMS`, creates a **draft** GitHub Release with auto-generated categorized notes, attaches zip + checksums + SBOM |

5. **Review the draft release** on GitHub — check the generated notes
   (categories come from `.github/release.yml` labels), then **Publish**.

6. **Sign before client distribution** (optional but recommended): run
   `Build/Sign-Release.ps1` locally against the extracted zip — CI verifies
   signatures but cannot sign (no cert in CI, by design).

## Client verification

Ship the `SHA256SUMS` line with any zip you hand to a client:

```powershell
(Get-FileHash .\NRG-Assessment-v4.13.0.zip -Algorithm SHA256).Hash
# must match the value in SHA256SUMS
```

## Rules

- Tags are immutable once published — never move or delete a released tag
  (enforce with a tag ruleset: Settings → Rules → New tag ruleset →
  target `v*` → block deletion + non-fast-forward).
- Version bumps to the pinned dependency ranges in the manifest
  (`Microsoft.Graph.Authentication` < 3.0, `ExchangeOnlineManagement` < 4.0)
  are their own PR with a full-suite run — never part of a release commit.

<!-- Thanks for contributing to TenantPosture. Fill out the relevant sections; delete the ones that don't apply. -->

## Summary

<!-- 1-3 sentences. What changed? Why? -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Documentation only
- [ ] Security fix
- [ ] Refactor / cleanup (no behavior change)
- [ ] CI / infrastructure

## Related issues

<!-- "Closes #N" / "Fixes #N" / "Refs #N" -->

## Test plan

<!-- How did you verify this? Bullet list of what was tested manually + what tests were added. -->

- [ ]
- [ ]

## Security checklist

Required for every PR. Tick what applies, explain anything skipped.

- [ ] **Read-only invariant intact.** No new tenant-write cmdlets in production paths (collectors / evaluators / publishers). `Apply-*` scripts are the sole sanctioned exception.
- [ ] **Input validation.** Every new parameter has `[ValidatePattern]` / `[ValidateSet]` / `[ValidateScript]` / `[ValidateRange]` as appropriate.
- [ ] **No new tenant data in plaintext logs.** Verified that `Write-Host` / `Write-Warning` lines don't echo UPNs, tokens, or PII beyond what `ConvertTo-TPHtmlSafe` already handles.
- [ ] **`-LiteralPath` on file ops.** No `-Path` wildcards on user-supplied input.
- [ ] **`-Encoding utf8`** on every `Out-File` / `Set-Content` that touches disk.
- [ ] **Errors surface, not swallowed.** New `try/catch` blocks either re-throw, register via `Register-TPException`, or write a `Write-Warning` declaring the consequence (don't silent-no-op a CI gate).
- [ ] **StrictMode-safe field access.** New code that reads from findings / metadata uses hashtable `.Contains(key)` or PSObject `.PSObject.Properties[key]` rather than bare `.Property` access that throws under StrictMode.
- [ ] **No hardcoded GUIDs / domains / secrets.** Permissions and tenant IDs resolved at runtime; secrets read from Cert: store or env vars.

## Tests

- [ ] Pester suite passes locally: `Invoke-Pester ./Testing/`
- [ ] PSScriptAnalyzer clean: `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1` returns no Error-severity findings
- [ ] If a new function, it has a Pester test
- [ ] If a new bug fix, it has a regression test naming the bug class
- [ ] If a new public surface, it has a doc note in `README.md` / `CHANGELOG.md`

## Documentation

- [ ] `CHANGELOG.md` updated under `## Unreleased`
- [ ] `README.md` reflects new flags / behavior if user-facing
- [ ] `CLAUDE.md` reflects new modules / functions if structural
- [ ] If this affects the security posture, `SECURITY.md` or `docs/SECURE-DEVELOPMENT.md` updated

## Reviewer notes

<!-- Anything specific the reviewer should look at. Files where the diff is large but trivial. Hidden gotchas. -->

---

By submitting this PR you confirm your contribution complies with the project's [security policy](../SECURITY.md) and [coding standards](../CONTRIBUTING.md).

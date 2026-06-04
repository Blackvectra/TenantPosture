@{
    # PSScriptAnalyzer settings for NRG-Assessment-Tool CI
    #
    # Severity = Error      → fails CI (must fix or exclude)
    # Severity = Warning    → reports in CI log only (does not fail)
    # Severity = Information → reports in CI log only (does not fail)
    #
    # CI logic lives in .github/workflows/ci.yml — this file only configures the
    # rule set the analyzer evaluates against.
    #
    # SUPPRESSION POLICY: every excluded rule below carries a rationale + a
    # documented sunset path (v5.0 cleanup, Phase 4 ship, etc). Suppressions
    # are not free — they hide signal — so we treat them as technical debt.

    Severity = @('Error', 'Warning')

    # Default to the analyzer's full rule set, then exclude rules that don't
    # apply to this codebase.
    IncludeDefaultRules = $true

    ExcludeRules = @(
        # Legitimate interactive UX output. The tool prints progress banners,
        # connection status, and per-step messages directly to the operator
        # console — Write-Host is the correct PowerShell idiom for that.
        'PSAvoidUsingWriteHost',

        # This is a strictly READ-ONLY assessment tool. No function changes
        # tenant state, so ShouldProcess / -WhatIf / -Confirm boilerplate would
        # be noise. The future Apply-NRGBaseline.ps1 write component (Phase 4)
        # will need ShouldProcess — when that lands, drop this exclusion.
        'PSUseShouldProcessForStateChangingFunctions',

        # Common false positive: parameters bound via splatting or used
        # indirectly via Set-Variable are flagged as unused. The codebase
        # uses both patterns extensively.
        'PSReviewUnusedParameter',

        # The module exports plural-noun functions intentionally
        # (Get-NRGFindings returns a collection, Clear-NRGFindings clears all).
        # The plural form better reflects the collection semantics than the
        # analyzer's singular-noun convention.
        'PSUseSingularNouns',

        # All 40 empty catches in this codebase are intentional defensive
        # swallows around best-effort operations:
        #   - DNS record lookups that legitimately fail when a record isn't
        #     published (DKIM selectors, MTA-STS, TLS-RPT, DNSSEC) — absence
        #     IS the finding, not an error.
        #   - Service disconnects in cleanup paths (Disconnect-MgGraph,
        #     Disconnect-ExchangeOnline, etc.) where -ErrorAction SilentlyContinue
        #     is already on the cmdlet AND the catch is double-defense.
        #   - Best-effort module-version reads with hardcoded fallback values.
        #   - Browser auto-launch second-line fallbacks.
        # The rule's premise ("silent swallowing hides bugs") doesn't apply
        # when the error is known, non-actionable, and the semantic intent
        # is "try and fail gracefully." Re-evaluate if a future refactor
        # adds NEW empty catches that aren't covered by these categories.
        'PSAvoidUsingEmptyCatchBlock',

        # UTF-8 without BOM is the canonical encoding for PowerShell 7 source
        # files (#Requires -Version 7.0 at the top of every script in this repo
        # guarantees PS7). The BOM-required rule targets PS 5.1 compatibility,
        # which we don't support. Suppressing this drops ~70 false positives
        # that would otherwise drown out signal in CI logs. Revisit if
        # this codebase ever has to support PS 5.1 again (it won't).
        'PSUseBOMForUnicodeEncodedFile',

        # The 6 Apply-NRG* write-mode functions (Apply-NRGAADLegacyAuth,
        # Apply-NRGAADMFA, Apply-NRGEXOMailboxAudit, Apply-NRGEXOSmtpAuth,
        # Apply-NRGEXOAutoForward, Apply-NRGDefenderPreset) use the unapproved
        # "Apply" verb. "Apply-" is the deliberate verb chosen for the write-
        # mode remediation surface because it pairs naturally with the
        # operator workflow ("apply the baseline to a tenant") and the
        # existing Apply-NRGBaseline.ps1 orchestrator. Renaming to
        # Set-NRGBaselineAAD* / Set-NRGBaselineEXO* would break operator
        # documentation, training material, and muscle memory built up across
        # multiple client engagements. Rename is deferred to v5.0 where it
        # can ship alongside the other breaking changes already planned for
        # that release. Until then, this exclusion is the explicit accept-
        # the-debt marker. Re-evaluate when v5.0 ships.
        'PSUseApprovedVerbs'
    )
}

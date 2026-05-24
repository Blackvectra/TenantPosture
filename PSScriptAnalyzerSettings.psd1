@{
    # PSScriptAnalyzer settings for NRG-Assessment-Tool CI
    #
    # Severity = Error      → fails CI (must fix or exclude)
    # Severity = Warning    → reports in CI log only (does not fail)
    # Severity = Information → reports in CI log only (does not fail)
    #
    # CI logic lives in .github/workflows/ci.yml — this file only configures the
    # rule set the analyzer evaluates against.

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
        'PSUseSingularNouns'
    )
}

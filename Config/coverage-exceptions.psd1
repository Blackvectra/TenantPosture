@{
    # ── Coverage honesty exceptions ──────────────────────────────────────────
    # Controls whose entry in controls.json claims Automated = $true but whose
    # evaluator cannot (yet) produce BOTH a pass (Satisfied) and a fail
    # (Gap/Partial) from tenant data — i.e. it does not genuinely discriminate.
    #
    # Every such control MUST be listed here with a Kind and a Reason. The CI
    # honesty-gate (Testing/NRG.CoverageHonesty.Tests.ps1) fails the build if:
    #   * a non-discriminating Automated control is NOT listed here, or
    #   * a listed control has STARTED discriminating (stale entry — delete it), or
    #   * an entry is missing its Kind or Reason.
    # This is what keeps "195 automated controls" an honest, machine-verified
    # claim rather than a marketing number.
    #
    # Kind = 'Manual'
    #     No supported tenant-scope read API exists, so the control genuinely
    #     needs human verification. These are candidates to flip Automated=$false
    #     in controls.json (a product-claim change, done deliberately).
    # Kind = 'ImplementationPending'
    #     Automatable with an existing or near-term API/cmdlet — tracked coverage
    #     debt to convert from advisory to a real discriminating check.
    #
    # Verified against the evaluator ASTs via Get-NRGControlAutomationAudit.

    Exceptions = @(
        # ── Manual: no supported read surface ────────────────────────────────
        @{ ControlId = 'DEF-3.3'; Kind = 'Manual'; Reason = 'Defender for Cloud Apps connection status has no supported Graph/EXO read API.' }
        @{ ControlId = 'DEF-3.4'; Kind = 'Manual'; Reason = 'Defender alert email-notification config is not exposed by any supported read API.' }
        @{ ControlId = 'DEF-4.3'; Kind = 'Manual'; Reason = 'Risky-application alerting requires Defender for Cloud Apps; no read API.' }
        @{ ControlId = 'DEF-4.4'; Kind = 'Manual'; Reason = 'The Priority account user tag is not exposed by any supported Graph/EXO read API.' }
        @{ ControlId = 'AAD-8.1'; Kind = 'Manual'; Reason = 'PIM alert configuration is not reliably readable across tenant PIM tiers.' }
        @{ ControlId = 'PVW-3.1'; Kind = 'Manual'; Reason = 'SIEM/audit export configuration has no supported read API.' }
        @{ ControlId = 'PVW-3.3'; Kind = 'Manual'; Reason = 'Purview Compliance Manager score has no supported programmatic read API.' }
        @{ ControlId = 'TMS-3.4'; Kind = 'Manual'; Reason = 'Teams chat-copy / retention nuance requires manual portal verification.' }
        @{ ControlId = 'EXO-2.6'; Kind = 'Manual'; Reason = 'Shared-mailbox sign-in blocked state is per-user; no reliable tenant-scope signal.' }
        @{ ControlId = 'EXO-3.4'; Kind = 'Manual'; Reason = 'Alert-policy volume/threshold review has no supported read API.' }
        @{ ControlId = 'PPL-1.3'; Kind = 'Manual'; Reason = 'Power Platform setting not exposed by the admin API used by the collector.' }

        # ── ImplementationPending: automatable, tracked coverage debt ─────────
        @{ ControlId = 'AAD-13.1'; Kind = 'ImplementationPending'; Reason = 'Microsoft Graph security/secureScores exposes the current Secure Score — buildable.' }
        @{ ControlId = 'AAD-8.2';  Kind = 'ImplementationPending'; Reason = 'Graph identityGovernance/accessReviews exposes access-review definitions — buildable.' }
        @{ ControlId = 'EXO-2.3';  Kind = 'ImplementationPending'; Reason = 'Get-CASMailboxPlan / Get-CASMailbox exposes POP3 enablement — buildable.' }
        @{ ControlId = 'EXO-2.4';  Kind = 'ImplementationPending'; Reason = 'Get-CASMailboxPlan / Get-CASMailbox exposes IMAP enablement — buildable.' }
        @{ ControlId = 'EXO-3.2';  Kind = 'ImplementationPending'; Reason = 'Get-HostedOutboundSpamFilterPolicy exposes outbound recipient/message limits — buildable.' }
        @{ ControlId = 'SPO-2.4';  Kind = 'ImplementationPending'; Reason = 'SPO tenant DenyAddAndCustomizePages setting is collectable — buildable.' }
        @{ ControlId = 'SPO-2.5';  Kind = 'ImplementationPending'; Reason = 'SPO third-party storage tenant setting is collectable — buildable.' }
        @{ ControlId = 'SPO-3.1';  Kind = 'ImplementationPending'; Reason = 'Site collection administrators are enumerable via SPO/PnP — buildable.' }
        @{ ControlId = 'SPO-3.3';  Kind = 'ImplementationPending'; Reason = 'Version-history / library retention settings are collectable — buildable.' }
    )
}

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
        @{ ControlId = 'DEF-4.4'; Kind = 'Manual'; Reason = 'The Priority account user tag is not exposed by any supported Graph/EXO read API.' }
        @{ ControlId = 'AAD-8.1'; Kind = 'Manual'; Reason = 'PIM alert configuration is not reliably readable across tenant PIM tiers.' }
        @{ ControlId = 'PVW-3.1'; Kind = 'Manual'; Reason = 'SIEM/audit export configuration has no supported read API.' }
        @{ ControlId = 'PVW-3.3'; Kind = 'Manual'; Reason = 'Purview Compliance Manager score has no supported programmatic read API.' }
        # Verified per-site / deprecated — no tenant-level read signal:
        @{ ControlId = 'SPO-2.4'; Kind = 'Manual'; Reason = 'Custom-script (DenyAddAndCustomizePages) is a per-site-collection setting; Microsoft removed the tenant-level default, so it needs per-site enumeration, not a tenant read.' }
        @{ ControlId = 'SPO-3.1'; Kind = 'Manual'; Reason = 'Site collection administrators require per-site enumeration (Get-SPOUser / Get-SPOSite owners per site) — not a tenant-level signal.' }
    )
}

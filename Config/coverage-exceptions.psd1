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
        @{ ControlId = 'AAD-5.1'; Kind = 'Manual'; Reason = 'The user SSPR setting (None/Selected/All) has no supported Graph read; authorizationPolicy.allowedToUseSSPR is the ADMINISTRATOR setting.' }
        @{ ControlId = 'AAD-5.2'; Kind = 'Manual'; Reason = 'The number of methods required to reset a password lives in the legacy SSPR policy, which has no supported read API.' }
        @{ ControlId = 'PPL-3.4'; Kind = 'Manual'; Reason = 'Copilot Studio agent publishing channels are not exposed by Graph; an app registration publisherDomain is the tenant domain, not a channel.' }
        @{ ControlId = 'AAD-10.3'; Kind = 'Manual'; Reason = 'Break-glass sign-in alerting is configured in Sentinel / Defender XDR / Azure Monitor, which the assessment does not read.' }
        @{ ControlId = 'PVW-3.3'; Kind = 'Manual'; Reason = 'Purview Compliance Manager score has no supported programmatic read API.' }
        @{ ControlId = 'PVW-2.4'; Kind = 'Manual'; Reason = 'Insider Risk Management policies are not exposed through the Security & Compliance PowerShell or Graph surfaces this tool reads.' }
        @{ ControlId = 'PVW-3.2'; Kind = 'Manual'; Reason = 'eDiscovery readiness (roles assigned, a documented legal-hold workflow) is not measurable from the tenant; a case count only says whether there has been litigation.' }
        # Verified per-site / deprecated — no tenant-level read signal:
        @{ ControlId = 'SPO-2.4'; Kind = 'Manual'; Reason = 'Custom-script (DenyAddAndCustomizePages) is a per-site-collection setting; Microsoft removed the tenant-level default, so it needs per-site enumeration, not a tenant read.' }
        @{ ControlId = 'SPO-3.1'; Kind = 'Manual'; Reason = 'Site collection administrators require per-site enumeration (Get-SPOUser / Get-SPOSite owners per site) — not a tenant-level signal.' }
        @{ ControlId = 'SPO-2.3'; Kind = 'Manual'; Reason = 'The SharePoint Store app-acquisition setting is not among the fields Graph /admin/sharepoint/settings or Get-SPOTenant expose to this tool; the evaluator reports NotApplicable rather than guessing.' }
    )
}

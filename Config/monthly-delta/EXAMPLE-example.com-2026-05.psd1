# Monthly delta — EXAMPLE — May 2026
#
# TEMPLATE ONLY. Every value below is illustrative. Do not put a real client
# name, domain, or their live unremediated findings in a file that is tracked
# in git — a named organization next to a list of its open security gaps is
# the most sensitive shape this data takes, and git history is permanent.
# Real per-tenant files are gitignored; see the pattern in .gitignore.
#
# This file is the operator's per-month edit. The Publish-NRGMonthlyReport
# publisher reads it and renders the Work Completed / In Progress / Queued
# tables in the monthly HTML.
#
# One file per tenant per month. Filename convention:
#     <tenant-domain>-<YYYY-MM>.psd1
# e.g.
#     example.com-2026-05.psd1
#
# After the report runs, save the matching <name>.json output as the next
# month's -PriorMonthPath input so trend deltas render correctly. The
# tool wires this automatically when run via:
#     Invoke-NRGAssessment.ps1 -MonthlyReport \
#         -DeltaPath  ./Config/monthly-delta/<tenant>-<YYYY-MM>.psd1 \
#         -PriorMonth ./output/<tenant>/monthly/<tenant>-<prior YYYY-MM>.json
#
# Required keys: Period, EntityType, TLP. Everything else is optional.
# Each row in the three arrays takes:
#     @{ Service = '<one-line>'; ControlId = '<NRG-control-id or empty>'; Status = '<state>' }
# The Status field is optional — defaults to Complete / In Progress / Queued
# per which array the row lives in. The ControlId drives the HIPAA safeguard
# lookup; controls.json must have a HIPAA-prefixed FrameworkIds entry on
# that ControlId for the citation to render (otherwise it shows '—').

@{
    Period      = 'May 2026'
    EntityType  = 'Example Sector · Regulated Entity'
    TLP         = 'WHITE'   # WHITE | GREEN | AMBER | RED — drives header pill
                            # A real client file is normally AMBER or RED.
                            # This template is WHITE because it contains
                            # nothing about anyone.

    # Items completed THIS period. Each row appears under "Work Completed
    # This Period" with a green pill.
    NewlyCompleted = @(
        @{ Service = 'Baseline M365/Entra security assessment delivered — full control set across identity, email, data protection, collaboration, and endpoint'; ControlId = '' }
        @{ Service = 'Regulatory control mapping — findings mapped to the applicable framework safeguards and NIST CSF 2.0';                                       ControlId = '' }
        @{ Service = 'Prioritized remediation roadmap produced — gaps sequenced into phases with scoped effort';                                                   ControlId = '' }
        @{ Service = 'Security awareness training enrolled — phishing simulation and workforce training';                                                          ControlId = '' }
    )

    # Items moved into active work this period (or carried over from prior).
    # Render under "In Progress — Phase 1 Remediation" with amber pill.
    MovedToProgress = @(
        @{ Service = 'External email forwarding remediation — BEC persistence / unauthorized data copy risk'; ControlId = 'EXO-6.1' }
        @{ Service = 'Phishing-resistant MFA for administrators (FIDO2)';                                     ControlId = 'AAD-1.3' }
        @{ Service = 'Legacy authentication blocked via Conditional Access';                                  ControlId = 'AAD-1.1' }
        @{ Service = 'Conditional Access policy deployment';                                                  ControlId = 'AAD-2.1' }
        @{ Service = 'Defender Safe Attachments and Safe Links — anti-malware / anti-phishing';               ControlId = 'DEF-1.1' }
    )

    # Items scoped for future phases. Render under "Queued / Service
    # Roadmap" with indigo pill.
    AddedToQueue = @(
        @{ Service = 'Managed detection and response deployment — 24/7 endpoint monitoring and triage';      ControlId = 'INT-2.1' }
        @{ Service = 'Endpoint management via Intune — device compliance, AV, ASR rules, firewall, LAPS';    ControlId = 'INT-1.1' }
        @{ Service = 'Backup and recovery posture — mailbox hold coverage and retention windows';            ControlId = 'EXO-9.1' }
        @{ Service = 'Email authentication hardening — DKIM publication, MTA-STS enforce, CAA records';      ControlId = 'DNS-1.2' }
    )
}

# Manual-review answers — example
#
# Copy to Config/manual-review/<client-domain>.psd1 and fill in. The file
# name is the client name slugged, the same rule Config/ssp/*.psd1 uses:
# example.com -> example.com.psd1, "Acme Widgets" -> acme-widgets.psd1.
# Publish-NRGManualReviewQuestionnaire finds it automatically from
# -ClientName.
#
# This file holds the human half of the controls.json manual-review
# questionnaire — the answer for every control that has no automated test
# (Get-NRGAssessmentScope's NoProgrammaticCheck bucket) or that this run
# could not collect data for (its CollectionIncomplete bucket). It is the
# controls.json counterpart to Config/ssp/*.psd1, which does the same job
# for the 69-of-110 NIST 800-171 requirements the tenant scan cannot reach.
#
# Read with Import-PowerShellDataFile: data only, never executed. Do not put
# expressions, variables or code in it — they will not evaluate and the
# parse will fail.
#
# STATUS VALUES. Use exactly one of:
#
#   Fully implemented       in place today, and you can show the evidence
#                            named in Evidence.
#   Partially implemented   some of it is in place.
#   Not implemented         not in place and not yet planned.
#   Not applicable          does not apply to this tenant. REQUIRES
#                            NotApplicableReason, and the reason has to be
#                            about the tenant, not about it being
#                            inconvenient to configure.
#   Not assessed            evidence is still pending. Distinct from leaving
#                            the control out of this file entirely — this is
#                            an active "we know, we haven't gotten to it
#                            yet", not silence.
#   Compensating control    a different control covers the same risk.
#                            REQUIRES CompensatingControl, describing what it
#                            is and why it satisfies the intent.
#   Risk accepted            the gap is accepted rather than fixed.
#                            REQUIRES RiskAcceptance, naming who accepted it
#                            and when the acceptance expires — an acceptance
#                            with no expiration is not a decision, it is a
#                            gap nobody has to revisit.
#
# Omitting a control entirely is fine and honest. It renders in the
# questionnaire as "not yet answered", which is a truthful "we have not
# gotten to this one" and is far better than a guessed status.

@{

    Controls = @{

        'SPO-2.4' = @{
            Status  = 'Compensating control'
            Owner   = 'IT Manager'
            Evidence = 'Custom script is disabled tenant-wide via the SharePoint admin center default; the site-collection-level review this control asks for is not automated, but the tenant default already denies it and no site has been granted an exception.'
            CompensatingControl = 'Tenant-wide default of DenyAddAndCustomizePages=Disabled, verified quarterly by IT via Get-SPOSite -Limit All | Select Url,DenyAddAndCustomizePages, with results filed in the change log.'
        }

        'PVW-3.1' = @{
            Status   = 'Not implemented'
            Owner    = 'IT Manager'
            Evidence = 'No SIEM is deployed. Microsoft 365 audit logs are retained in the default 90-day window and reviewed manually on request only.'
            Poam     = @{
                Weakness  = 'No continuous log export or automated alerting exists outside Microsoft 365 itself.'
                Remedy    = 'Evaluate Microsoft Sentinel connector for the tenant, scoped to sign-in and admin-activity logs first.'
                Owner     = 'IT Manager'
                DueDate   = '2026-06-30'
            }
        }

        'DEF-3.3' = @{
            Status  = 'Risk accepted'
            Owner   = 'Operations Manager'
            Evidence = 'Defender for Cloud Apps is not licensed for this tenant.'
            RiskAcceptance = 'Accepted by the Operations Manager, 2026-01-14, on the basis of tenant size; review at next license renewal, 2027-01-14.'
        }
    }
}

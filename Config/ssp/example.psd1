# SSP answers — example
#
# Copy to Config/ssp/<client-domain>.psd1 and fill in. The file name is the
# client name slugged: example.com -> example.com.psd1, "Acme Widgets" ->
# acme-widgets.psd1. Publish-NRGSSP finds it automatically from -ClientName.
#
# This file holds the part of a System Security Plan that no scan can produce.
# The assessment evidences 41 of the 110 NIST SP 800-171 Rev 2 requirements
# from the tenant and the endpoints. The remaining 69 are policy, process,
# physical security and personnel — the answers are in someone's head or in a
# binder, and an SSP is not a document until they are written down here.
#
# Read with Import-PowerShellDataFile: data only, never executed. Do not put
# expressions, variables or code in it — they will not evaluate and the parse
# will fail.
#
# STATUS VALUES. Use exactly one of:
#
#   Implemented            in place today, and you can show an assessor the
#                          evidence named in Narrative.
#   Partially implemented  some of it is in place. Pair with a Poam block.
#   Planned                not in place; there is a dated plan. Needs a Poam.
#   Not implemented        not in place and not yet planned. Needs a Poam.
#   Not applicable         does not apply to this system. REQUIRES
#                          NotApplicableReason, and the reason has to be about
#                          the system, not about it being inconvenient. "We
#                          have no wireless" is a reason. "We do not do that"
#                          is not, and an assessor will say so.
#   Inherited              satisfied by a provider. REQUIRES InheritedFrom, and
#                          the provider must actually claim it — check their
#                          customer responsibility matrix rather than assuming.
#
# Omitting a requirement entirely is fine and honest. It renders as whatever
# the assessment found, or as "No automated evidence" where the assessment
# found nothing. That is a truthful "we have not answered this yet" and is far
# better than a guessed Implemented, which is a false statement in a document
# the client signs.
#
# A Status set here OVERRIDES what the assessment derived, and is stamped as
# client-attested wherever it renders. It never counts as tool-verified.

@{

    System = @{
        Name        = 'Example Client Microsoft 365 Environment'
        Owner       = 'Jane Doe, Operations Manager'
        Description = 'Microsoft 365 E3 tenant with Entra ID identity, Exchange Online mail, SharePoint and OneDrive storage, and Intune-managed Windows endpoints. Supports estimating, project management and accounting for a defence subcontractor.'
        Boundary    = 'The Microsoft 365 tenant, all Entra ID identities, all Intune-enrolled endpoints, and the site network at the head office. Excludes the manufacturing OT network, which is air-gapped and covered by a separate plan.'
        CuiTypes    = @('Controlled Technical Information (CTI)', 'Export Controlled (ITAR)')
        AssessedBy  = 'NRG Technology Services'
    }

    # What a service provider satisfies on the client's behalf. Named here so
    # the SSP can say where a requirement is met rather than leaving it blank.
    # Only list a provider that genuinely claims the requirement in writing.
    Inherited = @{
        'Microsoft 365 GCC High' = 'FedRAMP High authorised. Physical and environmental protection (3.10.x) for the datacentre, media sanitisation for cloud storage, and datacentre personnel screening. See the Microsoft customer responsibility matrix for the split.'
    }

    Requirements = @{

        # ── Answers the assessment cannot reach ─────────────────────────────

        '3.2.1' = @{
            Status          = 'Implemented'
            ResponsibleRole = 'Operations Manager'
            Narrative       = 'All staff complete security awareness training within 5 business days of hire and annually thereafter, delivered through KnowBe4. Role-specific modules are assigned to finance and to anyone with administrative access. Completion records are exported quarterly and retained for three years.'
        }

        '3.8.3' = @{
            Status          = 'Implemented'
            ResponsibleRole = 'IT Manager'
            Narrative       = 'Drives and media leaving service are destroyed by a NAID AAA certified vendor, who issues a certificate of destruction per batch. Certificates are filed against the asset tag in the asset register. Devices with soldered storage are cryptographically erased and the erase confirmation is retained.'
        }

        '3.9.2' = @{
            Status          = 'Partially implemented'
            ResponsibleRole = 'Operations Manager'
            Narrative       = 'Termination triggers an account disable through the HR offboarding checklist, usually the same day. Access is reviewed on role change but the review is not currently evidenced in writing.'
            Poam            = @{
                Weakness  = 'Role-change access reviews are performed but not documented, so there is no evidence to show an assessor.'
                Remedy    = 'Add a signed access-review step to the role-change form and retain the completed forms with the personnel file.'
                Owner     = 'Operations Manager'
                DueDate   = '2026-03-31'
                Resources = 'Internal, approximately 4 hours to amend the form and brief managers.'
            }
        }

        '3.10.1' = @{
            Status        = 'Inherited'
            InheritedFrom = 'Microsoft 365 GCC High'
            Narrative     = 'Physical access to the systems processing CUI is controlled by Microsoft at the datacentre. Head office physical access is covered separately under the site security plan; no CUI is stored on premises outside the tenant.'
        }

        '3.1.16' = @{
            Status              = 'Not applicable'
            NotApplicableReason = 'The system has no wireless access points. The head office network is wired throughout and wireless is not deployed on any segment within the boundary. Verified against the network diagram dated 2026-01-14.'
        }

        # ── Overriding what the assessment found ────────────────────────────
        #
        # Legitimate when the tenant scan cannot see the whole requirement. The
        # override is stamped as client-attested wherever it renders and never
        # merges into the tool-verified count — that separation is the point.

        '3.5.3' = @{
            Status          = 'Implemented'
            ResponsibleRole = 'IT Manager'
            Narrative       = 'MFA is enforced for all users through Conditional Access, evidenced by control AAD-1.2. The two break-glass accounts are excluded by design; both use 40-character passwords held in a sealed envelope in the safe, sign-in is alerted on, and quarterly use reviews are filed. That exclusion is why the assessment reports this requirement short of complete.'
        }
    }
}

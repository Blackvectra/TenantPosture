# Vendor evidence for a Copilot deployment in a government cloud

This is a reference for an MSP preparing a government-cloud client for
Microsoft Copilot. It describes three kinds of vendor-side document, what the
public record establishes about each, and what none of them establishes for a
specific tenant.

The short version: these documents are about **Microsoft's service**. The
assessment and the [AI use readiness review](TP-AI-USE-REVIEW.md) are about
**the client's tenant**. A client needs both, and neither substitutes for the
other.

**How this note is sourced.** Every statement of fact below cites a public
Microsoft or United States government page, read on 2026-11-12. Where a
document is distributed only through a signed-in portal, this note says so and
does not restate its contents. The documents themselves are not in this
repository and must not be added to it.

## 1. FedRAMP authorization of the Microsoft 365 government clouds

**What the public record says**

- Microsoft states that Office 365 U.S. Government (GCC and GCC High) hold
  authorizations from US agencies, and that Office 365 U.S. Government Defense
  holds a provisional authorization from DISA.
  [Microsoft Learn: FedRAMP](https://learn.microsoft.com/en-us/compliance/regulatory/offering-fedramp)
- The same page lists the in-scope services for each environment. "Microsoft
  Copilot" appears in the lists for GCC, GCC High and DoD.
  [Microsoft Learn: FedRAMP](https://learn.microsoft.com/en-us/compliance/regulatory/offering-fedramp), section "Office 365 applicability and in-scope services"
- The FedRAMP Marketplace entry for package FR1824057433 is titled "Microsoft
  365 Government Community Cloud-High" and shows a High certification profile,
  type Rev5, status FedRAMP Certified.
  [FedRAMP Marketplace: FR1824057433](https://www.fedramp.gov/marketplace/products/FR1824057433/)
- Microsoft says its audit reports are available through its FedRAMP audit
  documents link, which leads to the Service Trust Portal.
  [Microsoft Learn: FedRAMP](https://learn.microsoft.com/en-us/compliance/regulatory/offering-fedramp), section "Office 365 audits, reports, and certificates"

**Not confirmed from a public page**

- The detailed list of services inside a package and the name of the
  independent assessor. A package overview document may list them; the public
  Marketplace page read for this note did not. Read the current package
  documentation before stating either.
- Whether Copilot Studio is inside an authorization. The public in-scope lists
  name "Microsoft Copilot"; do not infer agent coverage from that.

**What it does not establish for a specific tenant**

- That Copilot is licensed, assigned or enabled in the client's tenant.
- That the tenant is configured securely. Microsoft says the customer remains
  responsible: "you need to achieve your own authorizations for components
  outside these services", and it points customers to its own configuration
  guidance.
  [Microsoft Learn: FedRAMP](https://learn.microsoft.com/en-us/compliance/regulatory/offering-fedramp), section "Frequently asked questions"
- Anything about a different cloud. GCC, GCC High and DoD are separate
  environments; a document for one says nothing about another, or about a
  commercial tenant.

## 2. Third-party SSDF attestation letter

**What the public record says**

- The Secure Software Development Framework is NIST SP 800-218, "Secure
  Software Development Framework (SSDF) Version 1.1: Recommendations for
  Mitigating the Risk of Software Vulnerabilities", published February 2022.
  [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- CISA's Secure Software Development Attestation Form is the form by which
  software producers serving the federal government confirm specific security
  practices, submitted by email or through the Repository for Software
  Attestations and Artifacts. CISA marks that page as archived content that may
  not reflect current policy.
  [CISA: Secure Software Development Attestation Form](https://www.cisa.gov/secure-software-attestation-form)

**Not confirmed from a public page**

- The contents of any particular attestation letter: which product lines it
  names, which practices it lists, who signed it and how long it remains in
  effect. A letter of this kind is obtained from the vendor (for Microsoft,
  through the Service Trust Portal, which requires sign-in). This note does not
  restate one. Read the current letter and record its date, scope and term.
- How an assessor's letter relates to the producer's own attestation form. Read
  what the letter itself says about that.

**What it does not establish for a specific tenant**

- Anything about the tenant. The framework concerns how a vendor develops and
  builds software, not how a customer configures the service.
- Anything specific to Copilot, unless the letter names it.

## 3. Microsoft's DPIA guidance and templates

**What the public record says**

- Under the GDPR, a data controller prepares a Data Protection Impact
  Assessment for processing likely to result in a high risk to individuals.
  Microsoft says nothing inherent in its products necessarily requires one:
  whether a DPIA is needed "depends on the details and context of how you, as
  the data controller, deploy, configure, and use" the service.
  [Microsoft Learn: DPIA guidance for Office 365](https://learn.microsoft.com/compliance/regulatory/gdpr-dpia-office365)
- Microsoft publishes a customizable DPIA document as "a modifiable
  illustrative template" and says it "shouldn't be construed as legal advice".
  [Microsoft Learn: DPIA guidance for Office 365](https://learn.microsoft.com/compliance/regulatory/gdpr-dpia-office365), Part 3
- The required content of a DPIA (purposes, necessity and proportionality,
  risks, and the measures to address them) is summarized on
  [Microsoft Learn: Data Protection Impact Assessment for the GDPR](https://learn.microsoft.com/compliance/regulatory/gdpr-data-protection-impact-assessments).

**Not confirmed from a public page**

- A Copilot-specific DPIA template for public sector customers. Microsoft
  distributes documents of that kind outside the public pages read for this
  note, so its contents are not restated here. If a client holds one, use the
  client's current copy.

**What it does not establish for a specific tenant**

- Nothing, by itself. A template is a starting point: the controller completes
  the assessment for its own configuration and use.
- Any required setting or threshold.
- That a DPIA is required. That depends on the client's obligations; the GDPR
  does not apply to every organization.

## Where each fits beside the review

| Review section | What vendor evidence can inform | What still comes from the tenant |
|---|---|---|
| Copilot deployment gate | Nothing. The gate judges tenant settings only. | Every blocker control's verdict. |
| 1. Observed AI-related configuration | Whether Microsoft lists Copilot as in scope for the client's cloud. | Whether Copilot is licensed and assigned in this tenant. |
| 2 and 3. Safeguards and items needing attention | Nothing directly. | Whether each setting is in place. |
| 4. Organizational decisions: vendor terms and contractual review | Authorization records and attestation letters are the kind of evidence a client files here. | The client's own record that it reviewed them. The review shows this area as "Not recorded in this assessment"; it does not read or verify vendor documents. |
| 4. Organizational decisions: sensitive information, human review, accountability | A completed DPIA, where the client is required to have one. | The client's decisions and who made them. |

## How to use this with a client

1. Confirm which cloud the client's tenant is in.
2. Have the client obtain current copies of the vendor documents from the
   vendor and record each title, date and source. Do not store them in this
   repository or attach them to an issue or pull request.
3. Run a full assessment and the AI use readiness review for the tenant.
4. Keep the two apart when reporting: vendor documents speak to the service,
   the review speaks to the tenant.
5. Have the client record its own organizational decisions.

## Limits of this note

- The cited pages were read on 2026-11-12 and change. Re-read them before
  relying on any statement here.
- It is not legal or compliance advice, and it makes no determination about any
  client or tenant.
- The review does not record vendor documents.

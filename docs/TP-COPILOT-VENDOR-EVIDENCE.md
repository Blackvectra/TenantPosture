# Vendor evidence for a Copilot deployment in a government cloud

This is a reference for an MSP preparing a government-cloud client for Microsoft
365 Copilot. It explains what three kinds of Microsoft-side document establish,
what they do not, and where each fits beside the
[AI use readiness review](TP-AI-USE-REVIEW.md).

The short version: these documents are about **Microsoft's service**. The
assessment and the review are about **the client's tenant**. A client needs
both, and neither substitutes for the other.

The documents themselves are not in this repository. Obtain current copies from
the Microsoft Service Trust Portal and the FedRAMP Marketplace; they are revised
and re-issued, and a copy on file goes stale.

## The three documents

### 1. Third-party SSDF attestation letter

A letter from Microsoft's FedRAMP assessor (a third-party assessment
organization, 3PAO) stating that Microsoft follows the Secure Software
Development Framework practices of NIST SP 800-218 when it builds Microsoft
365, based on the FedRAMP and DoD annual assessment.

| | |
|---|---|
| Establishes | How Microsoft develops and builds the software: separated and protected build environments, multifactor authentication for those environments, source code supply chain steps, provenance, vulnerability checks before release and a disclosure program. |
| Covers | The product lines the letter names. The letter reviewed for this note named Microsoft 365 GCC, GCC High and DoD. |
| Does not establish | Anything about a client's tenant configuration. Anything specific to Copilot. Anything about commercial Microsoft 365. |
| Validity | The letter states its own term (one year from signature in the copy reviewed), conditional on Microsoft's continuous monitoring. Record the signature date. |
| Not the same as | The CISA/OMB self-attestation form a software producer submits to CISA's repository. The letter says so itself. |

### 2. FedRAMP Marketplace package overview

Microsoft's overview of a FedRAMP package: package id, certification type,
independent assessor, and the list of services inside the authorization with
their security category.

| | |
|---|---|
| Establishes | Which services are inside the authorization boundary and at what category. The GCC High overview reviewed for this note listed **Microsoft 365 Copilot** as a certified service at High, and listed SharePoint Advanced Management, Purview DLP, audit, retention, Insider Risk Management and Communication Compliance among the included capabilities. |
| Covers | One cloud environment per package. GCC, GCC High and DoD are separate; check the package that matches the client's tenant. |
| Does not establish | That a feature is licensed, enabled or configured in the client's tenant. That a service not named in the list is authorized: the overview reviewed did not name Copilot Studio, so do not infer agent coverage from it. |
| Check | The package id against the FedRAMP Marketplace entry, and the generated date on the overview. |

### 3. Build-your-own DPIA template for Microsoft 365 Copilot

Microsoft's template for a Data Protection Impact Assessment under the GDPR,
written for public sector customers. It follows the Irish Data Protection
Commission's sample format and carries illustrative answers.

| | |
|---|---|
| Establishes | Nothing by itself. It is a template: Microsoft says it is informational, is not legal advice, and must be adapted to how the customer has configured and uses Copilot. |
| Useful for | Its structure, and its list of risk areas with Microsoft's own example mitigations: breach notification, external access control, unintended internal access, business continuity, audit and monitoring, cloud policy enforcement, and data governance. |
| Applies to | Organizations subject to the GDPR or UK GDPR. For other clients it is a useful structure, not a requirement. |
| Does not establish | Any required setting or threshold. It says the customer, as data controller, conducts the risk assessment and operates the tenant-side measures. |

## Where each fits beside the review

| Review section | Vendor document that informs it | What still comes from the tenant |
|---|---|---|
| Copilot deployment gate | None. The gate judges tenant settings only. | Every blocker control's verdict. |
| 1. Observed AI-related configuration | Marketplace overview: confirms Copilot is in the authorized boundary for that cloud. | Whether Copilot is licensed and assigned in this tenant. |
| 2 and 3. Safeguards and items needing attention | DPIA template: Microsoft's example mitigations name multifactor authentication or security defaults, protected administrator accounts, audit logging, least privilege with access reviews, and DLP. | Whether each of those is in place. |
| 4. Organizational decisions: vendor terms and contractual review | SSDF letter and marketplace overview are the kind of evidence a client files here. | The client's own record that it reviewed them. The review shows this area as "Not recorded in this assessment"; it does not read or verify vendor documents. |
| 4. Organizational decisions: sensitive information, human review, accountability | DPIA template sections on purpose limitation, accuracy, data subject rights and sign-off. | The client's decisions and who made them. |
| Not checked: internal oversharing | DPIA template treats "unintended internal access" as its own risk. Marketplace overview lists SharePoint Advanced Management, the tooling Microsoft points to for it. | Which sites and files are shared with whom. The assessment does not read this today. |

## How to use this with a client

1. Confirm which cloud the client's tenant is in. A GCC High document says
   nothing about a GCC or commercial tenant.
2. Collect current copies of the vendor documents and record each title, date
   and source. Note the SSDF letter's signature date and term.
3. Run a full assessment and the AI use readiness review for the tenant.
4. Put the two side by side using the table above. Vendor documents answer
   "is the service authorized and how is it built". The review answers "how is
   this tenant configured".
5. Have the client record its organizational decisions. If the client is
   subject to the GDPR, the DPIA template is Microsoft's starting point for that
   record.

## Limits of this note

- It was written from one copy of each document, read in November 2026. Titles,
  package contents and terms change. Read the current copy before relying on
  any statement here.
- It is not legal or compliance advice, and it makes no determination about any
  client.
- The review does not record vendor documents today. Recording client-held
  evidence, shown as client-held and not verified by the tool, is on the
  [roadmap](ROADMAP.md).

# Exchange Online permissions for the distribution-list scan

`Invoke-TPAssessment.ps1 -DistributionListsOnly` signs in to **Exchange Online only** and runs
`Get-*` cmdlets. It needs read access to recipients and to mail-flow and anti-spam configuration, and
**no write role of any kind**. This page says exactly which cmdlets it calls, what Microsoft documents
about the access they need, what Microsoft does **not** document, and how to check it in a tenant
before the first live run.

> **Status: not yet validated against a live tenant.** The cmdlet list is derived from the code and
> pinned by a test. The role statements below are quotes from Microsoft Learn, fetched 2026-10-04.
> Microsoft publishes **no per-cmdlet role table**, so the minimum role set for these exact cmdlets is
> established in your tenant with the check in [Verify it in your tenant](#verify-it-in-your-tenant),
> not by this page.

## What the scan calls

Every Exchange call is a read. A static test fails if the collector names a cmdlet that is not `Get-*`.

| Cmdlet | Why the scan calls it |
|---|---|
| `Get-DistributionGroup` | Distribution lists and mail-enabled security groups: settings, owners, allowed senders, join setting |
| `Get-DistributionGroupMember` | Direct members of each list (no nested expansion) |
| `Get-DynamicDistributionGroup` | Dynamic distribution lists and their settings |
| `Get-DynamicDistributionGroupMember` | The calculated membership Microsoft stores on a dynamic list |
| `Get-Recipient` | Only a fallback: a preview of a dynamic list's filter when the cmdlet above is unavailable. Microsoft recommends `Get-EXORecipient` in Exchange Online |
| `Get-AcceptedDomain` | Which domains are the tenant's own, to find an own-domain entry on an allow list |
| `Get-TransportRule` | Mail flow rules that set SCL -1 (skip spam filtering), with their conditions |
| `Get-HostedConnectionFilterPolicy` | The IP Allow List |
| `Get-HostedContentFilterPolicy` | Allowed senders and allowed domains in anti-spam policies |
| `Get-HostedContentFilterRule` | Which custom anti-spam policy applies to anyone |

`Connect-ExchangeOnline` and `Get-ConnectionInformation` belong to the Exchange Online PowerShell module and run
on the workstation; they are not Exchange role-based access control (RBAC) checks.

### What the scan does not need

The worksheet **prints** commands for an administrator (`Set-DistributionGroup`, `Set-DynamicDistributionGroup`,
`Disable-TransportRule`, `Enable-TransportRule`, `Set-HostedConnectionFilterPolicy`,
`Set-HostedContentFilterPolicy`). The scan never runs them and its account needs none of the roles that run them.
Keep it that way: **the identity that observes is not the identity that changes things.** Microsoft's feature
permissions page lists the write roles (Organization Management or Recipient Management for distribution
groups, Organization Management or Hygiene Management for anti-spam, Organization Management for mail flow
rules); they belong to the administrator who reviews a bundle and applies it.

## What Microsoft documents

All quotes are from Microsoft Learn. Nothing here is NRG's judgment.

- **There is no per-cmdlet role table.** Each cmdlet page says "You need to be assigned permissions before you
  can run this cmdlet" and points to
  [Find the permissions required to run any Exchange cmdlet](https://learn.microsoft.com/powershell/exchange/find-exchange-cmdlet-permissions).
  That page's technique is `Get-ManagementRole -Cmdlet <name>`, then `Get-ManagementRoleAssignment` for each role
  returned. It does not work in Security & Compliance PowerShell, which this scan does not use.
- **Read-only role group.** [Exchange Online permissions](https://learn.microsoft.com/exchange/permissions-exo/permissions-exo):
  View-Only Organization Management: "Members can view the properties of any object in the Exchange Online
  organization." Its default roles are **View-Only Configuration** ("Views all of the organization and mail flow
  (non-recipient) settings in the organization") and **View-Only Recipients** ("View recipient properties and
  run message trace"). The Microsoft Entra role **Global Reader** maps to View-Only Organization Management.
- **Anti-spam and connection filter read access.** The Defender for Office 365 pages for
  [anti-spam policies](https://learn.microsoft.com/defender-office-365/anti-spam-policies-configure) and
  [connection filter policies](https://learn.microsoft.com/defender-office-365/connection-filter-policies-configure)
  give "Read-only access to policies" to "the **Global Reader**, **Security Reader**, or **View-Only Organization
  Management** role groups".
- **Certificate (app-only) sign-in.**
  [App-only authentication](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2) needs the
  `Exchange.ManageAsApp` application permission with admin consent, and a role for the application. The three
  documented options: assign a built-in Microsoft Entra role ("You can't customize or scope these roles"; Global
  Reader is among the roles supported for Exchange Online PowerShell), assign a **custom Exchange role group** to the
  application's service principal (`New-ServicePrincipal`, `Add-RoleGroupMember`; Microsoft recommends this when
  "You need to restrict the available commands in your application"), or combine them. The page's footnote says the
  **Security Administrator** role lacks the permissions for recipient management and anti-spam tasks, so it is not
  a fit for this scan.

## Which to use

| Situation | Use | Why |
|---|---|---|
| Interactive sign-in by an analyst, or GDAP | **Global Reader**, or membership in **View-Only Organization Management** | The documented read-only grants; no write role to withhold |
| Unattended certificate sign-in, least privilege | A **custom role group** holding the View-Only Recipients and View-Only Configuration roles, assigned to the application's service principal | Restricts the available commands; confirm the cmdlets below with the check in the next section before relying on it |
| Unattended certificate sign-in, simplest | The **Global Reader** Entra role on the application | Documented as supported; broader than the scan needs |

Do not use Global Administrator or Exchange Administrator for this scan. They can change what the scan only
needs to read.

## Verify it in your tenant

Microsoft's own technique, run once in an Exchange Online PowerShell session by an administrator, for every cmdlet in
the table above. It only reads:

```powershell
# For each cmdlet the scan calls, list the management roles that include it (read-only).
$cmdlets = 'Get-DistributionGroup','Get-DistributionGroupMember','Get-DynamicDistributionGroup','Get-DynamicDistributionGroupMember',
           'Get-Recipient','Get-AcceptedDomain','Get-TransportRule','Get-HostedConnectionFilterPolicy',
           'Get-HostedContentFilterPolicy','Get-HostedContentFilterRule'
foreach ($c in $cmdlets) {
    $roles = Get-ManagementRole -Cmdlet $c
    [pscustomobject]@{ Cmdlet = $c; Roles = ($roles.Name -join ', ') }
}
```

Then check that the role group or custom role group you intend to use contains at least one role from each row
(`Get-ManagementRoleAssignment -Role <role> -Delegating $false`). If a cmdlet is not covered, the scan reports that
section as not collected and says "Not assessed"; it never reads a missing section as clean.

When you have run this against a tenant, record the result below and change the status line at the top of this page.

| Date | Tenant | Role group or role used | Cmdlets covered | Notes |
|---|---|---|---|---|
| (not yet run) | | | | |

## Related

- [`AUTH-APP-ONLY.md`](AUTH-APP-ONLY.md) covers the Microsoft Graph permissions for the full assessment; it does not
  cover this Exchange-only scan.
- [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md) lists what the distribution-list scan has and has not been validated against.
- [`DL-REMEDIATION-VALIDATION-RUNBOOK.md`](DL-REMEDIATION-VALIDATION-RUNBOOK.md) is the one controlled test of the
  remediation records on a disposable cloud-only list; run it with a separate, write-capable identity.

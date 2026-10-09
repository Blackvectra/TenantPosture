# Validating the distribution-list remediation records on a disposable list

> **Status: not yet run.** The remediation records are built and unit-tested against stubbed objects. That shows the
> scan builds what it intends to and that every Compare returns the right True or False for a given object. It does
> **not** show that Exchange accepts the commands or that a rollback restores the real configuration. This is the one
> controlled test that does.

Run it once, in a **test or non-production tenant**, on a **disposable cloud-only distribution list**. Keep the
tenant-wide records (DL-3.1, DL-3.2, DL-3.3) **out of this first test**: they change filtering for every recipient and
need their own change window.

## What you need

- A test tenant, an Exchange Online sign-in for the **scan** (read-only; see
  [`EXCHANGE-RBAC-DISTRIBUTION-LISTS.md`](EXCHANGE-RBAC-DISTRIBUTION-LISTS.md)) and a **separate** sign-in for the
  administrator who applies a record (Organization Management or Recipient Management). The identity that observes is
  not the identity that changes things.
- The Exchange Online PowerShell module at the floor the scan checks.
- Nothing else in the tenant that you care about: every object below is created for this test and deleted at the end.

## 1. Create the disposable objects

The commands below are for you to run as the applying administrator. They are not part of the scan.

```powershell
# One disposable cloud-only list, and one without an external member, so DL-1.1 is not held for a business-purpose review.
New-DistributionGroup -Name 'NRG-Validation-Open' -Alias 'tp-validation-open' -Type Distribution
New-DistributionGroup -Name 'NRG-Validation-Ext'  -Alias 'tp-validation-ext'  -Type Distribution
# Make DL-1.1 a shortfall on the first list: accept mail from outside the organization.
Set-DistributionGroup -Identity 'tp-validation-open' -RequireSenderAuthenticationEnabled $false
Set-DistributionGroup -Identity 'tp-validation-ext'  -RequireSenderAuthenticationEnabled $false
# One external member on the second list, so the allowed-senders manual action has something to propose.
New-MailContact -Name 'NRG Validation Vendor' -ExternalEmailAddress 'vendor@example.invalid'
Add-DistributionGroupMember -Identity 'tp-validation-ext' -Member 'vendor@example.invalid'
```

Write down the exact value of every property the records will change before you start, from Exchange itself and not
from the worksheet (`Get-DistributionGroup -Identity <list> | Format-List *`). That is your independent copy of the
original state.

## 2. Run the scan and read the worksheet

```powershell
.\Invoke-TPAssessment.ps1 -DistributionListsOnly -UserPrincipalName <scan-account> -TenantDomain <test-tenant>
```

For each validation list, confirm that **State read** and **Captured value, exact (JSON)** match your independent copy.
If they differ, stop: the scan read the wrong thing, and nothing below is meaningful.

## 3. Walk one record end to end

For each record in the table below, in this order, and **record what happened at every step**, including the exact
text of any error:

1. **Check.** Run the Check and its Compare. The Compare must print `True`. If it prints `False`, stop.
2. **Preview.** Run it. Confirm it changes nothing (`Get-DistributionGroup` shows the original value).
3. **Apply.** Run it. For a manual action this is the **Change** step, and it has no rollback command.
4. **Verify.** Run the Verify and its Compare. The Compare must print `True`.
5. **Rollback** (a bundle only). Run it, then its Compare. It must print `True`, which is the proof the captured value
   came back. Then run the Check's Compare once more.
6. **Undo** (a manual action only). Carry out the guidance in words, then run the Check's Compare. It must print `True`.

| Record | List | Why it is in the test |
|---|---|---|
| DL-1.1 bundle | `NRG-Validation-Open` | The simplest reversible bundle: a boolean captured `False`, set `$true`, restored `$false` |
| DL-2.5 bundle | `NRG-Validation-Open` | Needs an approved join standard in a **local, uncommitted** copy of `Config/tp-standards.json`; restores the captured value (for example `ApprovalRequired`, not `Open`) |
| DL-1.2 manual action | `NRG-Validation-Ext` | The allowed-senders proposal. No rollback command; test the **Undo** in words |
| DL-2.2 manual action | either | Only if you turn moderation on with no moderator; same shape as DL-1.2 |

DL-2.1 (an ownerless list) is **not testable here**: Exchange gives a new list its creator as owner, and Microsoft says
a list must keep at least one.

## 4. Things the scan could not settle from documentation

Record the observed behavior of each. These are the open questions the worksheet states in words.

- Does `Set-DistributionGroup -AcceptMessagesOnlyFromSendersOrMembers $null` clear the allowed senders? (Microsoft's
  cmdlet page does not document it. Observe it as a **separate** step; the worksheet does not offer it as a rollback.)
- Does Exchange accept the external contact's **primary SMTP address** as an allowed sender?
- What does `Get-DistributionGroup -IncludeAcceptMessagesOnlyFromSendersOrMembersWithDisplayNames` return for the allowed
  senders (GUIDs, names, addresses)? The Compare is a count because the scan assumes it cannot compare addresses.
- Does `-WhatIf` on `Set-DistributionGroup` print what it would change, and nothing else?

## 5. Record the result and clean up

| Date | Tenant | Record | Check | Preview | Apply | Verify Compare | Rollback or Undo | Compare after | Notes |
|---|---|---|---|---|---|---|---|---|---|
| (not yet run) | | | | | | | | | |

```powershell
Remove-DistributionGroup -Identity 'tp-validation-open' -Confirm:$false
Remove-DistributionGroup -Identity 'tp-validation-ext'  -Confirm:$false
Remove-MailContact -Identity 'vendor@example.invalid' -Confirm:$false
```

## What a pass and a failure mean

- **Pass** (every Compare printed `True`, including after the rollback or the undo): change the status line at the top
  of this page and the matching bullets in [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md), and record the date above. One list is
  one data point: repeat on a second tenant before relying on it.
- **A Compare printed `False` where it should print `True`**: the record, not the tenant, is wrong. Do not "fix" the
  Compare to match; find out whether the live value was different from what the scan captured or the comparison is
  wrong, and add a test that fails first.
- **Exchange rejected a command**: the catalog template is wrong. Record the exact error, correct the template in
  `Config/distribution-list-baseline.json`, and add the case to `TP.DistributionListRemediation.Tests.ps1`.

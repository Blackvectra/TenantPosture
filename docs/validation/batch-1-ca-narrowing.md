# Batch 1: Conditional Access scope narrowing (D1, D2)

Expected behavior, written before the code change. The tests in
`Testing/TP.CANarrowing.Tests.ps1` are written against this page.

## Defects

- **D1. Guest and external-user exclusions are ignored.** The shared coverage
  helper (`Lib/Get-TPEffectiveCoverage.ps1`) read a policy's user, group and role
  exclusions only. A policy for All users that excludes guests or external users
  (`conditions.users.excludeGuestsOrExternalUsers`) counted as covering everyone.
- **D2. A policy limited to an authentication flow counts as every sign-in.**
  `Get-TPCANarrowing` never read `conditions.authenticationFlows`. A policy that
  applies only to device-code or authentication-transfer sign-ins counted as
  covering every sign-in. AAD-1.3 checked flows on its own; no other caller did.

## Authoritative sources

All are Microsoft Graph v1.0 resource pages, checked 2026-10-31:

- **`conditionalAccessUsers`:** `excludeGuestsOrExternalUsers` is optionally
  populated. `excludeUsers` and `includeUsers` may hold the legacy value
  `GuestsOrExternalUsers`.
- **`conditionalAccessGuestsOrExternalUsers`:**
  - `guestOrExternalUserTypes` is multi-valued. Its values are `none`,
    `internalGuest`, `b2bCollaborationGuest`, `b2bCollaborationMember`,
    `b2bDirectConnectUser`, `otherExternalUser`, `serviceProvider` and
    `unknownFutureValue`.
  - `externalTenants` is either all tenants or a collection of tenant IDs.
- **`conditionalAccessAuthenticationFlows`:** `transferMethods` holds `none`,
  `deviceCodeFlow`, `authenticationTransfer` or `unknownFutureValue`.

## Rules

1. **A guest exclusion narrows the individual policy for the guest types it
   names.** It is recorded beside the policy's user, group and role exclusions as
   one population per guest type: `guests:<type>`, or
   `guests:<type>:tenants:<ids>` when only listed external organizations are
   excluded. `none` excludes nothing. The legacy value `GuestsOrExternalUsers` in
   `excludeUsers` means every guest and external type.
2. **Credit is kept for the populations the policies demonstrably protect.**
   - **Every qualifying policy excludes the same guest type:** that type is
     reported as not covered (a shortfall). The finding stays Partial, never
     Satisfied, and the members' coverage stays in Verified.
   - **One qualifying policy has no guest exclusion:** coverage is Full, as
     before.
3. **A complementary guest policy can close the gap.** It must deliver the same
   protection (the caller has already filtered on grant and state), apply to all
   applications with no other narrowing, and include guests and external users of
   the excluded type.
   - **It excludes nothing and covers the same external organizations or more:**
     that guest type is covered.
   - **It has its own exclusions:** whether those guests are covered is not
     established. The control is not assessed (when nothing else is wrong), and
     the limitation is named. Uncertainty is never turned into a shortfall.
   - **It has no use** (no all-user policy excludes guests): it is reported like
     any other narrower policy.
4. **External organizations that cannot be compared stay unproven.** When two
   policies exclude a guest type for listed external organizations and the lists
   are unknown (a results file written before the list was collected), they are
   never treated as the same exclusion.
5. **A guest population is never an emergency-access principal.** The finding
   does not offer the approval record for it, and the approval pass says so if
   one is attempted.
6. **An authentication-flow condition narrows the policy.** A policy whose
   `authenticationFlows.transferMethods` names a method other than `none` applies
   only to those flows. It no longer counts toward coverage of every sign-in
   (AAD-1.1, 1.2, 1.4, 1.5, 2.3, INT-1.2, sign-in frequency, token protection,
   privileged workstation, PIM authentication context). AAD-1.3 uses the same
   shared reason instead of its own copy.
7. **AAD-11.1 judges the device-code flow itself.** It passes `-AllowAuthFlows`,
   so a device-code block keeps its verdict.
8. **Demonstrated gaps are preserved.** A guest-type shortfall is reported even
   when another component of the same control (MFA registration, for example)
   could not be read. In that case the control is Partial, with the unread part
   named.

## Not in this batch

Insider-risk conditions, the application filter, the Conditional Access view's
own template matching, and every reporting or schema change.

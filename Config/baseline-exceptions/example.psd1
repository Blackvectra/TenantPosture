@{
    # NRG Security Baseline — approved exceptions for ONE client.
    #
    # File name: Config/baseline-exceptions/<tenant-domain>.psd1, where
    # <tenant-domain> is the CONNECTED tenant's domain with every character
    # other than letters, digits, '.' and '-' removed (the same rule the SSP
    # answers file uses). Copy this file and rename it; 'example' is never
    # loaded for a real tenant.
    #
    # Read with Import-PowerShellDataFile: data only, never executed, so it
    # is safe to email between the MSP and the client.
    #
    # An exception changes a control's baseline DISPOSITION to
    # ApprovedException. It never changes the observed state: a Failed
    # control with an approved exception is still reported as Failed with
    # an approved exception, so the gap stays visible.
    #
    # An exception is approved only when every required field is present and
    # ReviewDate has not passed. ExpiryDate is optional; once it passes the
    # exception is ignored and the control is a baseline gap again.

    Exceptions = @(
        @{
            ControlId           = 'EXO-1.2'
            Reason              = 'Two multifunction printers relay through Exchange Online with SMTP AUTH; the client has no on-premises relay.'
            CompensatingControl = 'Per-mailbox SMTP AUTH enabled on the two printer mailboxes only (EXO-7.4 lists them); long random passwords; mailboxes cannot sign in interactively.'
            Approver            = 'jane.doe@nrgtechservices.com'
            ApprovedDate        = '2026-09-01'
            ReviewDate          = '2027-03-01'
            # ExpiryDate        = '2027-09-01'
        }
    )

    # Emergency-access (break-glass) accounts a Conditional Access policy may
    # exclude. A Conditional Access control that finds the same principal(s)
    # excluded from every qualifying policy reports a shortfall (Partial);
    # when every such principal is on this record, current and approved, the
    # finding becomes "Satisfied with approved emergency-access exceptions"
    # and names them. The record is the approval: an account's name alone
    # establishes nothing. ObjectId is the Entra object id the exclusion
    # carries. Kind is User (default) or Group; a group approval attests that
    # the group holds only emergency-access accounts, because the assessment
    # does not resolve membership, and the finding says so. A role is never
    # emergency access. ReviewDate and ExpiryDate follow the same rules as an
    # exception above.
    EmergencyAccess = @(
        @{
            ObjectId          = '00000000-0000-0000-0000-000000000001'
            Kind              = 'User'
            UserPrincipalName = 'breakglass1@contoso.onmicrosoft.com'
            Reason            = 'Emergency access account per Microsoft guidance; excluded from every Conditional Access policy, monitored by alert.'
            Approver          = 'jane.doe@nrgtechservices.com'
            ApprovedDate      = '2026-09-01'
            ReviewDate        = '2027-03-01'
            # ExpiryDate      = '2027-09-01'
        }
    )
}

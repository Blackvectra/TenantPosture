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
}

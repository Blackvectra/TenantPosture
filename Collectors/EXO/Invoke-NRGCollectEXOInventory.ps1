#Requires -Version 7.0
#
# Invoke-NRGCollectEXOInventory.ps1  (v4.5.5)
# Per-mailbox inventory for named findings:
#   - Mailboxes with external forwarding rules
#   - Shared mailboxes with sign-in enabled
#   - Mailboxes with audit logging disabled
#   - Mailboxes with SMTP AUTH explicitly enabled (individual overrides)
#

function Invoke-NRGCollectEXOInventory {
    [CmdletBinding()] param()

    $result = @{
        Success = $false
        Data = @{
            ForwardingMailboxes    = @()
            SharedMailboxSignIn    = @()
            AuditDisabledMailboxes = @()
            SmtpAuthEnabledPerUser = @()
            InboxRulesForwarding   = @()
        }
    }

    try {
        # Mailboxes with external forwarding (ForwardingSmtpAddress set)
        try {
            $fwd = @(Get-Mailbox -ResultSize 1000 -Filter "ForwardingSmtpAddress -ne `$null" -ErrorAction Stop)
            $result.Data.ForwardingMailboxes = @($fwd | ForEach-Object {
                @{
                    DisplayName           = [string]$_.DisplayName
                    UPN                   = [string]$_.UserPrincipalName
                    ForwardingAddress     = [string]$_.ForwardingSmtpAddress
                    DeliverToMailboxAndForward = [bool]$_.DeliverToMailboxAndForward
                    MailboxType           = [string]$_.RecipientTypeDetails
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-ForwardingMailboxes' -Message $_.Exception.Message
            }
        }

        # Shared mailboxes with AccountEnabled (should be BlockCredential = $true)
        try {
            $shared = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize 500 -ErrorAction Stop)
            # For shared mailboxes, sign-in is blocked when AccountEnabled = $false on the user object
            # We proxy this by checking if a license is assigned (licensed shared = sign-in possible)
            $result.Data.SharedMailboxSignIn = @($shared | Where-Object {
                # SharedMailboxes with a license assigned can have interactive sign-in
                $_.LicenseReconciliationNeeded -eq $true -or
                $_.ProhibitSendQuota -lt '100 GB' -and $_.RecipientTypeDetails -eq 'SharedMailbox'
            } | Select-Object -First 50 | ForEach-Object {
                @{
                    DisplayName   = [string]$_.DisplayName
                    PrimarySmtp   = [string]$_.PrimarySmtpAddress
                    MailboxType   = [string]$_.RecipientTypeDetails
                    LicenseNeeded = [bool]$_.LicenseReconciliationNeeded
                }
            })
            # More reliable: check via Graph if the AD account is enabled
            # Stored separately for evaluator to join
            $result.Data.AllSharedMailboxes = @($shared | ForEach-Object {
                @{
                    DisplayName  = [string]$_.DisplayName
                    PrimarySmtp  = [string]$_.PrimarySmtpAddress
                    Guid         = [string]$_.Guid
                    ExternalEmailAddress = [string]$_.ExternalEmailAddress
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SharedMailbox' -Message $_.Exception.Message
            }
        }

        # Mailboxes with audit explicitly disabled
        try {
            $noAudit = @(Get-Mailbox -ResultSize 1000 -Filter "AuditEnabled -eq `$false" -ErrorAction Stop)
            $result.Data.AuditDisabledMailboxes = @($noAudit | ForEach-Object {
                @{
                    DisplayName  = [string]$_.DisplayName
                    UPN          = [string]$_.UserPrincipalName
                    MailboxType  = [string]$_.RecipientTypeDetails
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-AuditDisabled' -Message $_.Exception.Message
            }
        }

        # Per-user SMTP AUTH enabled (bypasses org-level disable)
        try {
            $smtpEnabled = @(Get-CASMailbox -ResultSize 1000 -ErrorAction Stop | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false })
            $result.Data.SmtpAuthEnabledPerUser = @($smtpEnabled | Select-Object -First 50 | ForEach-Object {
                @{
                    DisplayName = [string]$_.DisplayName
                    UPN         = [string]$_.Name
                }
            })
        } catch {
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'EXO-SMTPAuthPerUser' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-Inventory' -Status 'Collected'
        }
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'EXO-Inventory' -Message $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-Inventory' -Data $result
    }
    return $result
}
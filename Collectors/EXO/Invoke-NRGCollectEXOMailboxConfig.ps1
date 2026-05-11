#
# Invoke-NRGCollectEXOMailboxConfig.ps1
# Collects Exchange Online tenant-wide and mailbox-level configurations.
# COLLECTION ONLY - no scoring.
#

function Invoke-NRGCollectEXOMailboxConfig {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'EXO-MailboxConfig'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # Tenant-level config
        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
        $result.Data['OrganizationConfig'] = @{
            AuditDisabled                   = if ($null -ne $orgConfig.AuditDisabled) { $orgConfig.AuditDisabled } else { $false }
            CustomerLockBoxEnabled          = if ($null -ne $orgConfig.CustomerLockBoxEnabled) { $orgConfig.CustomerLockBoxEnabled } else { $null }
            ConnectorsEnabled               = if ($null -ne $orgConfig.ConnectorsEnabled) { $orgConfig.ConnectorsEnabled } else { $null }
            ConnectorsEnabledForOutlook     = if ($null -ne $orgConfig.ConnectorsEnabledForOutlook) { $orgConfig.ConnectorsEnabledForOutlook } else { $null }
            EwsEnabled                      = if ($null -ne $orgConfig.EwsEnabled) { $orgConfig.EwsEnabled } else { $null }
            OAuth2ClientProfileEnabled      = if ($null -ne $orgConfig.OAuth2ClientProfileEnabled) { $orgConfig.OAuth2ClientProfileEnabled } else { $null }
            UnifiedAuditLogIngestionEnabled = if ($orgConfig.PSObject.Properties['UnifiedAuditLogIngestionEnabled']) { $orgConfig.UnifiedAuditLogIngestionEnabled } else { $null }
            PublicFoldersEnabled            = if ($null -ne $orgConfig.PublicFoldersEnabled) { $orgConfig.PublicFoldersEnabled } else { $null }
            FocusedInboxOn                  = if ($null -ne $orgConfig.FocusedInboxOn) { $orgConfig.FocusedInboxOn } else { $null }
        }

        # Transport config (SMTP AUTH)
        $transportConfig = Get-TransportConfig -ErrorAction Stop
        $result.Data['TransportConfig'] = @{
            SmtpClientAuthenticationDisabled = $transportConfig.SmtpClientAuthenticationDisabled
            ExternalDelayDsnEnabled          = $transportConfig.ExternalDelayDsnEnabled
            InternalDelayDsnEnabled          = $transportConfig.InternalDelayDsnEnabled
        }

        # All mailboxes - protocol settings
        $casMailboxes = @(Get-CasMailbox -ResultSize Unlimited -ErrorAction Stop)
        $result.Data['MailboxProtocols'] = @{
            TotalMailboxes      = $casMailboxes.Count
            PopEnabled          = @($casMailboxes | Where-Object PopEnabled).Count
            ImapEnabled         = @($casMailboxes | Where-Object ImapEnabled).Count
            ActiveSyncEnabled   = @($casMailboxes | Where-Object ActiveSyncEnabled).Count
            EwsEnabled          = @($casMailboxes | Where-Object EwsEnabled).Count
            MapiEnabled         = @($casMailboxes | Where-Object MapiEnabled).Count
            OWAEnabled          = @($casMailboxes | Where-Object OWAEnabled).Count
            SmtpClientAuthDisabled = @($casMailboxes | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $true }).Count
        }

        # Mailbox audit bypass detection
        try {
            $auditBypass = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction Stop | Where-Object AuditBypassEnabled -eq $true)
            $result.Data['AuditBypass'] = @{
                BypassedCount = $auditBypass.Count
                BypassedMailboxes = @($auditBypass | Select-Object -ExpandProperty Identity)
            }
        } catch {
            $result.Exceptions += "AuditBypass query failed: $($_.Exception.Message)"
        }

        # Shared mailbox protocol audit
        try {
            $sharedMailboxes = @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop)
            $sharedSmtps = @($sharedMailboxes | ForEach-Object { $_.PrimarySmtpAddress } | Where-Object { $_ })

            # Build hashset only when we have addresses (avoids .ctor null exception)
            $sharedSet = if ($sharedSmtps.Count -gt 0) {
                [System.Collections.Generic.HashSet[string]]::new([string[]]$sharedSmtps, [System.StringComparer]::OrdinalIgnoreCase)
            } else {
                [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }

            $sharedCas = @($casMailboxes | Where-Object { $sharedSet.Contains($_.PrimarySmtpAddress) })

            $result.Data['SharedMailboxes'] = @{
                Count           = $sharedMailboxes.Count
                SignInEnabled   = @($sharedMailboxes | Where-Object { $_.AccountDisabled -ne $true }).Count
                PopEnabled      = @($sharedCas | Where-Object PopEnabled).Count
                ImapEnabled     = @($sharedCas | Where-Object ImapEnabled).Count
                MFAEnforced     = 'See AAD-CAPolicies for shared mailbox MFA enforcement'
            }
        } catch {
            $result.Exceptions += "SharedMailboxes query failed: $($_.Exception.Message)"
        }

        $result.Success = $true
        Register-NRGCoverage -Family 'EXO-MailboxConfig' -Status 'Collected'
    }
    catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'EXO-MailboxConfig' -Message $_.Exception.Message
        Register-NRGCoverage -Family 'EXO-MailboxConfig' -Status 'Failed' -Note $_.Exception.Message
    }

    Set-NRGRawData -Key 'EXO-MailboxConfig' -Data $result
    return $result
}

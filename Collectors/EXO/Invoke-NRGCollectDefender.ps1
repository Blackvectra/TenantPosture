#Requires -Version 7.0
#
# Invoke-NRGCollectDefender.ps1  (v4.5.5)
# Collects Defender for Office 365 policy configuration.
# READ-ONLY. Each policy type collected independently — MDO P1/P2 not required
# (cmdlets throw if unlicensed; caught per-section, registered as exceptions).
#
# Required session: Exchange Online (Connect-ExchangeOnline)
# Requires Defender for Office 365 Plan 1 or Plan 2 for Safe Attachments/Links.
#
# NIST SP 800-53: SI-3 (malicious code protection), SI-4 (system monitoring), SI-8 (spam protection)
# MITRE ATT&CK:   T1566 (Phishing), T1204.002 (Malicious File), T1598 (Phishing for Info)
#

function Invoke-NRGCollectDefender {
    [CmdletBinding()] param()

    $result = @{
        Success    = $false
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Data       = @{}
    }

    try {
        # ── Safe Attachments ──────────────────────────────────────────────
        # SI-3: Attachment sandboxing — Defender for Office 365 P1+
        try {
            $saPolicies = @(Get-SafeAttachmentPolicy -ErrorAction Stop)
            $saRules    = @(Get-SafeAttachmentRule   -ErrorAction Stop)

            $result.Data['SafeAttachments'] = @{
                Available              = $true
                Policies               = @($saPolicies | ForEach-Object {
                    @{
                        Name             = [string]$_.Name
                        IsDefault        = [bool]$_.IsDefault
                        Enable           = [bool]($_.Enable ?? $false)
                        Action           = [string]($_.Action ?? 'Allow')
                        ActionOnError    = [bool]($_.ActionOnError ?? $false)
                        Redirect         = [bool]($_.Redirect ?? $false)
                        RedirectAddress  = [string]($_.RedirectAddress ?? '')
                        OperationMode    = [string]($_.OperationMode ?? 'Delay')
                    }
                })
                Rules                  = @($saRules | ForEach-Object {
                    @{
                        Name                  = [string]$_.Name
                        SafeAttachmentPolicy  = [string]$_.SafeAttachmentPolicy
                        State                 = [string]$_.State
                        Priority              = $_.Priority
                        RecipientDomainIs     = @($_.RecipientDomainIs ?? @())
                    }
                })
                EnabledNonDefaultCount = @($saPolicies | Where-Object { -not $_.IsDefault -and $_.Enable -eq $true }).Count
                BlockActionCount       = @($saPolicies | Where-Object { $_.Action -eq 'Block' }).Count
                AnyBlockEnabled        = @($saPolicies | Where-Object { $_.Action -eq 'Block' -and ($_.Enable ?? $false) }).Count -gt 0
            }
        } catch {
            $result.Data['SafeAttachments'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-SafeAttachments' -Message $_.Exception.Message
            }
        }

        # ── Safe Links ────────────────────────────────────────────────────
        # SI-3: URL detonation and time-of-click protection — Defender P1+
        try {
            $slPolicies = @(Get-SafeLinksPolicy -ErrorAction Stop)
            $slRules    = @(Get-SafeLinksRule   -ErrorAction Stop)

            $result.Data['SafeLinks'] = @{
                Available              = $true
                Policies               = @($slPolicies | ForEach-Object {
                    @{
                        Name                         = [string]$_.Name
                        IsDefault                    = [bool]$_.IsDefault
                        EnableSafeLinksForEmail      = [bool]($_.EnableSafeLinksForEmail ?? $false)
                        EnableSafeLinksForTeams      = [bool]($_.EnableSafeLinksForTeams ?? $false)
                        EnableSafeLinksForOffice     = [bool]($_.EnableSafeLinksForOffice ?? $false)
                        ScanUrls                     = [bool]($_.ScanUrls ?? $false)
                        EnableForInternalSenders     = [bool]($_.EnableForInternalSenders ?? $false)
                        AllowClickThrough            = [bool]($_.AllowClickThrough ?? $true)
                        TrackClicks                  = [bool]($_.TrackClicks ?? $false)
                        DisableUrlRewrite            = [bool]($_.DisableUrlRewrite ?? $false)
                        DeliverMessageAfterScan      = [bool]($_.DeliverMessageAfterScan ?? $false)
                    }
                })
                Rules                  = @($slRules | ForEach-Object {
                    @{
                        Name              = [string]$_.Name
                        SafeLinksPolicy   = [string]$_.SafeLinksPolicy
                        State             = [string]$_.State
                        Priority          = $_.Priority
                        RecipientDomainIs = @($_.RecipientDomainIs ?? @())
                    }
                })
                EnabledNonDefaultCount = @($slPolicies | Where-Object { -not $_.IsDefault -and $_.EnableSafeLinksForEmail }).Count
            }
        } catch {
            $result.Data['SafeLinks'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-SafeLinks' -Message $_.Exception.Message
            }
        }

        # ── Anti-Phishing (Defender layer) ────────────────────────────────
        # SI-4: Impersonation and spoof detection
        try {
            $apPolicies = @(Get-AntiPhishPolicy -ErrorAction Stop)
            $apRules    = @(Get-AntiPhishRule   -ErrorAction Stop)

            $result.Data['AntiPhishing'] = @{
                Available = $true
                Policies  = @($apPolicies | ForEach-Object {
                    @{
                        Name                                     = [string]$_.Name
                        IsDefault                                = [bool]$_.IsDefault
                        Enabled                                  = [bool]($_.Enabled ?? $true)
                        EnableMailboxIntelligence                = [bool]($_.EnableMailboxIntelligence ?? $false)
                        EnableMailboxIntelligenceProtection      = [bool]($_.EnableMailboxIntelligenceProtection ?? $false)
                        EnableOrganizationDomainsProtection      = [bool]($_.EnableOrganizationDomainsProtection ?? $false)
                        EnableTargetedUserProtection             = [bool]($_.EnableTargetedUserProtection ?? $false)
                        EnableSimilarUsersSafetyTips             = [bool]($_.EnableSimilarUsersSafetyTips ?? $false)
                        EnableSimilarDomainsSafetyTips           = [bool]($_.EnableSimilarDomainsSafetyTips ?? $false)
                        EnableUnusualCharactersSafetyTips        = [bool]($_.EnableUnusualCharactersSafetyTips ?? $false)
                        EnableSpoofIntelligence                  = [bool]($_.EnableSpoofIntelligence ?? $false)
                        EnableFirstContactSafetyTips             = [bool]($_.EnableFirstContactSafetyTips ?? $false)
                        EnableUnauthenticatedSender              = [bool]($_.EnableUnauthenticatedSender ?? $false)
                        EnableViaTag                             = [bool]($_.EnableViaTag ?? $false)
                        HonorDmarcPolicy                         = [bool]($_.HonorDmarcPolicy ?? $false)
                        PhishThresholdLevel                      = $_.PhishThresholdLevel
                        TargetedUserProtectionAction             = [string]($_.TargetedUserProtectionAction ?? 'NoAction')
                        TargetedDomainProtectionAction           = [string]($_.TargetedDomainProtectionAction ?? 'NoAction')
                        MailboxIntelligenceProtectionAction      = [string]($_.MailboxIntelligenceProtectionAction ?? 'NoAction')
                        SpoofQuarantineTag                       = [string]($_.SpoofQuarantineTag ?? '')
                        TargetedUsersToProtect                   = @($_.TargetedUsersToProtect ?? @())
                        TargetedDomainsToProtect                 = @($_.TargetedDomainsToProtect ?? @())
                    }
                })
                Rules = @($apRules | ForEach-Object {
                    @{
                        Name             = [string]$_.Name
                        AntiPhishPolicy  = [string]$_.AntiPhishPolicy
                        State            = [string]$_.State
                        Priority         = $_.Priority
                    }
                })
            }
        } catch {
            $result.Data['AntiPhishing'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-AntiPhishing' -Message $_.Exception.Message
            }
        }

        # ── Malware Filter ────────────────────────────────────────────────
        try {
            $mfPolicies = @(Get-MalwareFilterPolicy -ErrorAction Stop)

            $result.Data['MalwareFilter'] = @{
                Available = $true
                Policies  = @($mfPolicies | ForEach-Object {
                    @{
                        Name                     = [string]$_.Name
                        IsDefault                = [bool]$_.IsDefault
                        EnableFileFilter         = [bool]($_.EnableFileFilter ?? $false)
                        FileTypes                = @($_.FileTypes ?? @())
                        Action                   = [string]($_.Action ?? 'DeleteAttachmentAndUseDefaultAlertText')
                        EnableInternalSenderAdminNotifications = [bool]($_.EnableInternalSenderAdminNotifications ?? $false)
                    }
                })
                FileFilterEnabledCount = @($mfPolicies | Where-Object { $_.EnableFileFilter }).Count
            }
        } catch {
            $result.Data['MalwareFilter'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-MalwareFilter' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'Defender' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Defender-Collector' -Message $_.Exception.Message
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'Defender' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'Defender-Policies' -Data $result
    }
    return $result
}

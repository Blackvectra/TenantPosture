#
# Invoke-NRGCollectDefender.ps1
# Collects Microsoft Defender for Office 365 policy configurations.
# COLLECTION ONLY - no scoring.
#
# Requires: Exchange Online connection (EXO session)
# Requires: Defender for Office 365 Plan 1 or Plan 2 license for Safe Attachments/Links
# Graceful skip pattern: each policy type is collected independently.
# MDO not licensed = cmdlets throw — caught per-section, surfaced in Exceptions.
#
# NIST SP 800-53: SI-3, SI-4, SI-8
# MITRE ATT&CK:   T1566 (Phishing), T1204.002 (Malicious File)
#

function Invoke-NRGCollectDefender {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'Defender'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    # ── Safe Attachments ────────────────────────────────────────────────────
    # SI-3: Malicious code protection — attachment sandboxing
    try {
        $saPolices = @(Get-SafeAttachmentPolicy -ErrorAction Stop)
        $saRules   = @(Get-SafeAttachmentRule -ErrorAction Stop)

        $result.Data['SafeAttachments'] = @{
            Available = $true
            Policies  = $saPolices | Select-Object -Property @(
                'Name', 'IsDefault', 'Enable', 'Action',
                'ActionOnError', 'Redirect', 'RedirectAddress',
                'ScanTimeout', 'OperationMode'
            )
            Rules = $saRules | Select-Object -Property @(
                'Name', 'SafeAttachmentPolicy', 'State', 'Priority',
                'RecipientDomainIs', 'SentTo', 'SentToMemberOf'
            )
            EnabledNonDefaultCount = @($saPolices | Where-Object { -not $_.IsDefault -and $_.Enable -eq $true }).Count
            BlockActionCount       = @($saPolices | Where-Object { $_.Action -eq 'Block' }).Count
        }
    }
    catch {
        $result.Data['SafeAttachments'] = @{ Available = $false }
        $result.Exceptions += "SafeAttachments: $($_.Exception.Message)"
    }

    # ── Safe Links ─────────────────────────────────────────────────────────
    # SI-3: URL detonation and time-of-click protection
    try {
        $slPolicies = @(Get-SafeLinksPolicy -ErrorAction Stop)
        $slRules    = @(Get-SafeLinksRule -ErrorAction Stop)

        $result.Data['SafeLinks'] = @{
            Available = $true
            Policies  = $slPolicies | Select-Object -Property @(
                'Name', 'IsDefault', 'EnableSafeLinksForEmail',
                'EnableSafeLinksForTeams', 'EnableSafeLinksForOffice',
                'ScanUrls', 'EnableForInternalSenders',
                'AllowClickThrough', 'TrackClicks',
                'DisableUrlRewrite', 'DeliverMessageAfterScan'
            )
            Rules = $slRules | Select-Object -Property @(
                'Name', 'SafeLinksPolicy', 'State', 'Priority',
                'RecipientDomainIs', 'SentTo', 'SentToMemberOf'
            )
            EnabledNonDefaultCount = @($slPolicies | Where-Object {
                -not $_.IsDefault -and $_.EnableSafeLinksForEmail -eq $true
            }).Count
        }
    }
    catch {
        $result.Data['SafeLinks'] = @{ Available = $false }
        $result.Exceptions += "SafeLinks: $($_.Exception.Message)"
    }

    # ── Anti-Phishing ──────────────────────────────────────────────────────
    # SI-4: Impersonation and spoof detection
    try {
        $apPolicies = @(Get-AntiPhishPolicy -ErrorAction Stop)
        $apRules    = @(Get-AntiPhishRule -ErrorAction Stop)

        $result.Data['AntiPhishing'] = @{
            Available = $true
            Policies  = $apPolicies | Select-Object -Property @(
                'Name', 'IsDefault', 'Enabled',
                'EnableMailboxIntelligence',
                'EnableMailboxIntelligenceProtection',
                'EnableOrganizationDomainsProtection',
                'EnableSimilarUsersSafetyTips',
                'EnableSimilarDomainsSafetyTips',
                'EnableUnusualCharactersSafetyTips',
                'EnableSpoofIntelligence',
                'EnableFirstContactSafetyTips',
                'PhishThresholdLevel',
                'TargetedUserProtectionAction',
                'TargetedDomainProtectionAction',
                'MailboxIntelligenceProtectionAction',
                'AuthenticationFailAction',
                'TargetedUsersToProtect'
            )
            Rules = $apRules | Select-Object -Property @(
                'Name', 'AntiPhishPolicy', 'State', 'Priority',
                'RecipientDomainIs', 'SentTo', 'SentToMemberOf'
            )
            NonDefaultCount = @($apPolicies | Where-Object { -not $_.IsDefault }).Count
        }
    }
    catch {
        $result.Data['AntiPhishing'] = @{ Available = $false }
        $result.Exceptions += "AntiPhishing: $($_.Exception.Message)"
    }

    # ── ATP Policy for O365 (Safe Links/Attachments for Teams/SPO/OD) ──────
    try {
        $atpPolicy = Get-AtpPolicyForO365 -ErrorAction Stop
        $result.Data['AtpO365'] = @{
            Available                           = $true
            EnableATPForSPOTeamsODB             = $atpPolicy.EnableATPForSPOTeamsODB
            EnableSafeDocs                      = $atpPolicy.EnableSafeDocs
            AllowSafeDocsOpen                   = $atpPolicy.AllowSafeDocsOpen
            EnableSafeLinksForO365Clients       = $atpPolicy.EnableSafeLinksForO365Clients
        }
    }
    catch {
        $result.Data['AtpO365'] = @{ Available = $false }
        $result.Exceptions += "AtpO365: $($_.Exception.Message)"
    }

    $result.Success = $true
    Register-NRGCoverage -Family 'Defender' -Status 'Collected'
    Set-NRGRawData -Key 'Defender' -Data $result
    return $result
}

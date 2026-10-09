#Requires -Version 7.0
#
# Invoke-TPCollectDefender.ps1  (v4.5.5)
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

function Invoke-TPCollectDefender {
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
                        IsDefault        = [bool](Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IsBuiltInProtection = [bool](Get-TPObjectField -Item $_ -Key 'IsBuiltInProtection' -Default ([string]$_.Name -eq 'Built-In Protection Policy'))
                        RecommendedPolicyType = [string](Get-TPObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                        Enable           = [bool](Get-TPObjectField -Item $_ -Key 'Enable' -Default $false)
                        Action           = [string](Get-TPObjectField -Item $_ -Key 'Action' -Default 'Allow')
                        ActionOnError    = [bool](Get-TPObjectField -Item $_ -Key 'ActionOnError' -Default $false)
                        Redirect         = [bool](Get-TPObjectField -Item $_ -Key 'Redirect' -Default $false)
                        RedirectAddress  = [string](Get-TPObjectField -Item $_ -Key 'RedirectAddress' -Default '')
                        OperationMode    = [string](Get-TPObjectField -Item $_ -Key 'OperationMode' -Default 'Delay')
                    }
                })
                Rules                  = @($saRules | ForEach-Object {
                    @{
                        Name                  = [string]$_.Name
                        SafeAttachmentPolicy  = [string]$_.SafeAttachmentPolicy
                        State                 = [string]$_.State
                        Priority              = $_.Priority
                        RecipientDomainIs     = @(Get-TPObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-TPObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-TPObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-TPObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count
                    }
                })
                EnabledNonDefaultCount = @($saPolicies | Where-Object { -not (Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $false) -and (Get-TPObjectField -Item $_ -Key 'Enable' -Default $false) -eq $true }).Count
                BlockActionCount       = @($saPolicies | Where-Object { (Get-TPObjectField -Item $_ -Key 'Action' -Default 'Allow') -eq 'Block' }).Count
                AnyBlockEnabled        = @($saPolicies | Where-Object { (Get-TPObjectField -Item $_ -Key 'Action' -Default 'Allow') -eq 'Block' -and (Get-TPObjectField -Item $_ -Key 'Enable' -Default $false) }).Count -gt 0
            }
        } catch {
            $result.Data['SafeAttachments'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-SafeAttachments' -Message $_.Exception.Message
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
                        IsDefault                    = [bool](Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IsBuiltInProtection = [bool](Get-TPObjectField -Item $_ -Key 'IsBuiltInProtection' -Default ([string]$_.Name -eq 'Built-In Protection Policy'))
                        RecommendedPolicyType = [string](Get-TPObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                        EnableSafeLinksForEmail      = [bool](Get-TPObjectField -Item $_ -Key 'EnableSafeLinksForEmail' -Default $false)
                        EnableSafeLinksForTeams      = [bool](Get-TPObjectField -Item $_ -Key 'EnableSafeLinksForTeams' -Default $false)
                        EnableSafeLinksForOffice     = [bool](Get-TPObjectField -Item $_ -Key 'EnableSafeLinksForOffice' -Default $false)
                        ScanUrls                     = [bool](Get-TPObjectField -Item $_ -Key 'ScanUrls' -Default $false)
                        EnableForInternalSenders     = [bool](Get-TPObjectField -Item $_ -Key 'EnableForInternalSenders' -Default $false)
                        AllowClickThrough            = [bool](Get-TPObjectField -Item $_ -Key 'AllowClickThrough' -Default $true)
                        TrackClicks                  = [bool](Get-TPObjectField -Item $_ -Key 'TrackClicks' -Default $false)
                        DisableUrlRewrite            = [bool](Get-TPObjectField -Item $_ -Key 'DisableUrlRewrite' -Default $false)
                        DeliverMessageAfterScan      = [bool](Get-TPObjectField -Item $_ -Key 'DeliverMessageAfterScan' -Default $false)
                    }
                })
                Rules                  = @($slRules | ForEach-Object {
                    @{
                        Name              = [string]$_.Name
                        SafeLinksPolicy   = [string]$_.SafeLinksPolicy
                        State             = [string]$_.State
                        Priority          = $_.Priority
                        RecipientDomainIs = @(Get-TPObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-TPObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-TPObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-TPObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count
                    }
                })
                EnabledNonDefaultCount = @($slPolicies | Where-Object { -not (Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $false) -and (Get-TPObjectField -Item $_ -Key 'EnableSafeLinksForEmail' -Default $false) }).Count
            }
        } catch {
            $result.Data['SafeLinks'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-SafeLinks' -Message $_.Exception.Message
            }
        }

        # ── Safe Attachments for SharePoint / OneDrive / Teams (EXO-4.3) ──
        # A tenant-wide switch on Get-AtpPolicyForO365, independent of every
        # Safe Attachments mail policy.
        try {
            $atpO365 = @(Get-AtpPolicyForO365 -ErrorAction Stop) | Select-Object -First 1
            $result.Data['AtpPolicyForO365'] = @{
                Available               = $true
                EnableATPForSPOTeamsODB = Get-TPObjectField -Item $atpO365 -Key 'EnableATPForSPOTeamsODB' -Default $null
                EnableSafeDocs          = Get-TPObjectField -Item $atpO365 -Key 'EnableSafeDocs' -Default $null
            }
        } catch {
            $result.Data['AtpPolicyForO365'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-AtpPolicyForO365' -Message $_.Exception.Message
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
                        IsDefault                                = [bool](Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IsBuiltInProtection = [bool](Get-TPObjectField -Item $_ -Key 'IsBuiltInProtection' -Default ([string]$_.Name -eq 'Built-In Protection Policy'))
                        RecommendedPolicyType = [string](Get-TPObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')

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
                        RecipientDomainIs = @(Get-TPObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-TPObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-TPObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-TPObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count

                    }
                })
            }
        } catch {
            $result.Data['AntiPhishing'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-AntiPhishing' -Message $_.Exception.Message
            }
        }

        # ── Preset security policy rules ──────────────────────────────────
        # Standard / Strict presets are switched on and scoped by these rules
        # (EOP = anti-spam/anti-phish/anti-malware, ATP = Safe Links /
        # Safe Attachments). A preset POLICY object stays after the preset is
        # turned off, so its presence says nothing; the rule State does.
        $result.Data['PresetRules'] = @{ Available = $false; EOP = @(); ATP = @() }
        try {
            $mkPr = { param($r) @{
                Name = [string](Get-TPObjectField -Item $r -Key 'Name' -Default '')
                State = [string](Get-TPObjectField -Item $r -Key 'State' -Default '')
                RecipientDomainIs = @(@(Get-TPObjectField -Item $r -Key 'RecipientDomainIs' -Default @()) | Where-Object { $_ })
                SentTo = @(@(Get-TPObjectField -Item $r -Key 'SentTo' -Default @()) | Where-Object { $_ })
                SentToMemberOf = @(@(Get-TPObjectField -Item $r -Key 'SentToMemberOf' -Default @()) | Where-Object { $_ })
                # WHO the preset does not apply to: the exclusions, by identity, so a reader (and the
                # coverage judgment) can see them instead of a bare HasExceptions flag.
                ExceptIfSentTo = @(@(Get-TPObjectField -Item $r -Key 'ExceptIfSentTo' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                ExceptIfSentToMemberOf = @(@(Get-TPObjectField -Item $r -Key 'ExceptIfSentToMemberOf' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                ExceptIfRecipientDomainIs = @(@(Get-TPObjectField -Item $r -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                HasExceptions = [bool]@(@(Get-TPObjectField -Item $r -Key 'ExceptIfSentTo' -Default @()) + @(Get-TPObjectField -Item $r -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-TPObjectField -Item $r -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count } }
            $eop = @(Get-EOPProtectionPolicyRule -ErrorAction Stop)
            $atp = @()
            if (Get-Command Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue) { $atp = @(Get-ATPProtectionPolicyRule -ErrorAction Stop) }
            $result.Data['PresetRules'] = @{ Available = $true; EOP = @($eop | ForEach-Object { & $mkPr $_ }); ATP = @($atp | ForEach-Object { & $mkPr $_ }) }
        } catch {
            $result.Data['PresetRules'] = @{ Available = $false; EOP = @(); ATP = @(); Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-PresetRules' -Message $_.Exception.Message
            }
        }

        # ── Malware Filter ────────────────────────────────────────────────
        try {
            $mfPolicies = @(Get-MalwareFilterPolicy -ErrorAction Stop)
            # Which policies are actually applied (an enabled rule) decides who the
            # attachment filter covers; a policy that exists but applies to nobody
            # protects nobody. A failed rule read leaves Rules $null, never an empty
            # list, so the evaluator cannot mistake it for "no custom rules".
            $mfRules = $null
            try { $mfRules = @(Get-MalwareFilterRule -ErrorAction Stop) } catch {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Defender-MalwareFilterRules' -Message $_.Exception.Message
                }
            }

            $result.Data['MalwareFilter'] = @{
                Available = $true
                Rules     = $(if ($null -eq $mfRules) { $null } else { @($mfRules | ForEach-Object {
                    @{
                        Name              = [string]$_.Name
                        MalwareFilterPolicy = [string](Get-TPObjectField -Item $_ -Key 'MalwareFilterPolicy' -Default '')
                        State             = [string](Get-TPObjectField -Item $_ -Key 'State' -Default '')
                        Priority          = (Get-TPObjectField -Item $_ -Key 'Priority' -Default $null)
                        RecipientDomainIs = @(Get-TPObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-TPObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-TPObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-TPObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-TPObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ })
                    }
                }) })
                Policies  = @($mfPolicies | ForEach-Object {
                    @{
                        Name                     = [string]$_.Name
                        RecommendedPolicyType    = [string](Get-TPObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                        IsDefault                = [bool](Get-TPObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        EnableFileFilter         = [bool]($_.EnableFileFilter ?? $false)
                        ZapEnabled               = (Get-TPObjectField -Item $_ -Key 'ZapEnabled' -Default $null)
                        FileTypes                = @($_.FileTypes ?? @())
                        Action                   = [string](Get-TPObjectField -Item $_ -Key 'Action' -Default 'DeleteAttachmentAndUseDefaultAlertText')
                        EnableInternalSenderAdminNotifications = [bool]($_.EnableInternalSenderAdminNotifications ?? $false)
                    }
                })
                FileFilterEnabledCount = @($mfPolicies | Where-Object { $_.EnableFileFilter }).Count
            }
        } catch {
            $result.Data['MalwareFilter'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-MalwareFilter' -Message $_.Exception.Message
            }
        }

        # ── Attack Simulation Training campaigns — DEF-4.6 ────────────────
        # Graph endpoint (not an EXO cmdlet): needs AttackSimulation.Read.All
        # (v4.13 re-consent) and Defender for Office 365 P2. GLOBAL CLOUD ONLY —
        # US Gov L4/L5/DoD and China 21Vianet return 404. Caught either way so
        # AttackSimulations stays Available=$false and the evaluator routes to
        # NotApplicable in those clouds, never a false Gap.
        try {
            if (Get-Command Invoke-TPGraphRequest -ErrorAction SilentlyContinue) {
                # Paged: counting launched campaigns from the first 100 alone
                # could report none launched on a tenant with a long history.
                $simRows = @(Get-TPGraphAllPages `
                    -Uri 'https://graph.microsoft.com/v1.0/security/attackSimulation/simulations?$top=100')
                $sims = @($simRows | ForEach-Object {
                    @{
                        DisplayName    = [string]($_.displayName ?? '')
                        Status         = [string]($_.status ?? 'unknown')
                        AttackType     = [string]($_.attackType ?? 'unknown')
                        LaunchDateTime = [string]($_.launchDateTime ?? '')
                        IsAutomated    = [bool]($_.isAutomated ?? $false)
                    }
                })
                $result.Data['AttackSimulations'] = @{
                    Available = $true
                    Count     = $sims.Count
                    Simulations = $sims
                    # A launched/completed campaign — anything past draft — proves a
                    # real training program, not just a saved draft.
                    # 'scheduled' has not run yet: nobody has been tested.
                    LaunchedCount = @($sims | Where-Object { $_.Status -in @('running','succeeded','completed') }).Count
                    ScheduledCount = @($sims | Where-Object { $_.Status -eq 'scheduled' }).Count
                }
            } else {
                $result.Data['AttackSimulations'] = @{ Available = $false; Error = 'Graph proxy unavailable' }
            }
        } catch {
            $result.Data['AttackSimulations'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Defender-AttackSimulations' -Message $_.Exception.Message
            }
        }

        $result.Success = $true
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'Defender' -Status 'Collected'
        }

    } catch {
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'Defender-Collector' -Message $_.Exception.Message
        }
        if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
            Register-TPCoverage -Family 'Defender' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'Defender-Policies' -Data $result
    }
    return $result
}

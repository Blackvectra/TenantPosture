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
                        IsDefault        = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IsBuiltInProtection = [bool](Get-NRGObjectField -Item $_ -Key 'IsBuiltInProtection' -Default ([string]$_.Name -eq 'Built-In Protection Policy'))
                        RecommendedPolicyType = [string](Get-NRGObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                        Enable           = [bool](Get-NRGObjectField -Item $_ -Key 'Enable' -Default $false)
                        Action           = [string](Get-NRGObjectField -Item $_ -Key 'Action' -Default 'Allow')
                        ActionOnError    = [bool](Get-NRGObjectField -Item $_ -Key 'ActionOnError' -Default $false)
                        Redirect         = [bool](Get-NRGObjectField -Item $_ -Key 'Redirect' -Default $false)
                        RedirectAddress  = [string](Get-NRGObjectField -Item $_ -Key 'RedirectAddress' -Default '')
                        OperationMode    = [string](Get-NRGObjectField -Item $_ -Key 'OperationMode' -Default 'Delay')
                    }
                })
                Rules                  = @($saRules | ForEach-Object {
                    @{
                        Name                  = [string]$_.Name
                        SafeAttachmentPolicy  = [string]$_.SafeAttachmentPolicy
                        State                 = [string]$_.State
                        Priority              = $_.Priority
                        RecipientDomainIs     = @(Get-NRGObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-NRGObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-NRGObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count
                    }
                })
                EnabledNonDefaultCount = @($saPolicies | Where-Object { -not (Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false) -and (Get-NRGObjectField -Item $_ -Key 'Enable' -Default $false) -eq $true }).Count
                BlockActionCount       = @($saPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Action' -Default 'Allow') -eq 'Block' }).Count
                AnyBlockEnabled        = @($saPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Action' -Default 'Allow') -eq 'Block' -and (Get-NRGObjectField -Item $_ -Key 'Enable' -Default $false) }).Count -gt 0
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
                        IsDefault                    = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IsBuiltInProtection = [bool](Get-NRGObjectField -Item $_ -Key 'IsBuiltInProtection' -Default ([string]$_.Name -eq 'Built-In Protection Policy'))
                        RecommendedPolicyType = [string](Get-NRGObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')
                        EnableSafeLinksForEmail      = [bool](Get-NRGObjectField -Item $_ -Key 'EnableSafeLinksForEmail' -Default $false)
                        EnableSafeLinksForTeams      = [bool](Get-NRGObjectField -Item $_ -Key 'EnableSafeLinksForTeams' -Default $false)
                        EnableSafeLinksForOffice     = [bool](Get-NRGObjectField -Item $_ -Key 'EnableSafeLinksForOffice' -Default $false)
                        ScanUrls                     = [bool](Get-NRGObjectField -Item $_ -Key 'ScanUrls' -Default $false)
                        EnableForInternalSenders     = [bool](Get-NRGObjectField -Item $_ -Key 'EnableForInternalSenders' -Default $false)
                        AllowClickThrough            = [bool](Get-NRGObjectField -Item $_ -Key 'AllowClickThrough' -Default $true)
                        TrackClicks                  = [bool](Get-NRGObjectField -Item $_ -Key 'TrackClicks' -Default $false)
                        DisableUrlRewrite            = [bool](Get-NRGObjectField -Item $_ -Key 'DisableUrlRewrite' -Default $false)
                        DeliverMessageAfterScan      = [bool](Get-NRGObjectField -Item $_ -Key 'DeliverMessageAfterScan' -Default $false)
                    }
                })
                Rules                  = @($slRules | ForEach-Object {
                    @{
                        Name              = [string]$_.Name
                        SafeLinksPolicy   = [string]$_.SafeLinksPolicy
                        State             = [string]$_.State
                        Priority          = $_.Priority
                        RecipientDomainIs = @(Get-NRGObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-NRGObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-NRGObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count
                    }
                })
                EnabledNonDefaultCount = @($slPolicies | Where-Object { -not (Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false) -and (Get-NRGObjectField -Item $_ -Key 'EnableSafeLinksForEmail' -Default $false) }).Count
            }
        } catch {
            $result.Data['SafeLinks'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-SafeLinks' -Message $_.Exception.Message
            }
        }

        # ── Safe Attachments for SharePoint / OneDrive / Teams (EXO-4.3) ──
        # A tenant-wide switch on Get-AtpPolicyForO365, independent of every
        # Safe Attachments mail policy.
        try {
            $atpO365 = @(Get-AtpPolicyForO365 -ErrorAction Stop) | Select-Object -First 1
            $result.Data['AtpPolicyForO365'] = @{
                Available               = $true
                EnableATPForSPOTeamsODB = Get-NRGObjectField -Item $atpO365 -Key 'EnableATPForSPOTeamsODB' -Default $null
                EnableSafeDocs          = Get-NRGObjectField -Item $atpO365 -Key 'EnableSafeDocs' -Default $null
            }
        } catch {
            $result.Data['AtpPolicyForO365'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-AtpPolicyForO365' -Message $_.Exception.Message
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
                        IsDefault                                = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IsBuiltInProtection = [bool](Get-NRGObjectField -Item $_ -Key 'IsBuiltInProtection' -Default ([string]$_.Name -eq 'Built-In Protection Policy'))
                        RecommendedPolicyType = [string](Get-NRGObjectField -Item $_ -Key 'RecommendedPolicyType' -Default '')

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
                        RecipientDomainIs = @(Get-NRGObjectField -Item $_ -Key 'RecipientDomainIs' -Default @())
                        SentTo            = @(Get-NRGObjectField -Item $_ -Key 'SentTo' -Default @())
                        SentToMemberOf    = @(Get-NRGObjectField -Item $_ -Key 'SentToMemberOf' -Default @())
                        HasExceptions     = [bool]@(@(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-NRGObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count

                    }
                })
            }
        } catch {
            $result.Data['AntiPhishing'] = @{ Available = $false; Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-AntiPhishing' -Message $_.Exception.Message
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
                Name = [string](Get-NRGObjectField -Item $r -Key 'Name' -Default '')
                State = [string](Get-NRGObjectField -Item $r -Key 'State' -Default '')
                RecipientDomainIs = @(Get-NRGObjectField -Item $r -Key 'RecipientDomainIs' -Default @())
                SentTo = @(Get-NRGObjectField -Item $r -Key 'SentTo' -Default @())
                SentToMemberOf = @(Get-NRGObjectField -Item $r -Key 'SentToMemberOf' -Default @())
                HasExceptions = [bool]@(@(Get-NRGObjectField -Item $r -Key 'ExceptIfSentTo' -Default @()) + @(Get-NRGObjectField -Item $r -Key 'ExceptIfSentToMemberOf' -Default @()) + @(Get-NRGObjectField -Item $r -Key 'ExceptIfRecipientDomainIs' -Default @()) | Where-Object { $_ }).Count } }
            $eop = @(Get-EOPProtectionPolicyRule -ErrorAction Stop)
            $atp = @()
            if (Get-Command Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue) { $atp = @(Get-ATPProtectionPolicyRule -ErrorAction Stop) }
            $result.Data['PresetRules'] = @{ Available = $true; EOP = @($eop | ForEach-Object { & $mkPr $_ }); ATP = @($atp | ForEach-Object { & $mkPr $_ }) }
        } catch {
            $result.Data['PresetRules'] = @{ Available = $false; EOP = @(); ATP = @(); Error = $_.Exception.Message }
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-PresetRules' -Message $_.Exception.Message
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
                        IsDefault                = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        EnableFileFilter         = [bool]($_.EnableFileFilter ?? $false)
                        FileTypes                = @($_.FileTypes ?? @())
                        Action                   = [string](Get-NRGObjectField -Item $_ -Key 'Action' -Default 'DeleteAttachmentAndUseDefaultAlertText')
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

        # ── Attack Simulation Training campaigns — DEF-4.6 ────────────────
        # Graph endpoint (not an EXO cmdlet): needs AttackSimulation.Read.All
        # (v4.13 re-consent) and Defender for Office 365 P2. GLOBAL CLOUD ONLY —
        # US Gov L4/L5/DoD and China 21Vianet return 404. Caught either way so
        # AttackSimulations stays Available=$false and the evaluator routes to
        # NotApplicable in those clouds, never a false Gap.
        try {
            if (Get-Command Invoke-NRGGraphRequest -ErrorAction SilentlyContinue) {
                $simResp = Invoke-NRGGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/v1.0/security/attackSimulation/simulations?$top=100' `
                    -ErrorAction Stop
                $sims = @()
                if ($simResp -and $null -ne $simResp.value) {
                    $sims = @(@($simResp.value) | ForEach-Object {
                        @{
                            DisplayName    = [string]($_.displayName ?? '')
                            Status         = [string]($_.status ?? 'unknown')
                            AttackType     = [string]($_.attackType ?? 'unknown')
                            LaunchDateTime = [string]($_.launchDateTime ?? '')
                            IsAutomated    = [bool]($_.isAutomated ?? $false)
                        }
                    })
                }
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
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Defender-AttackSimulations' -Message $_.Exception.Message
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

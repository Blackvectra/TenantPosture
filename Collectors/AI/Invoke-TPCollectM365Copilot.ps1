#Requires -Version 7.0
#
# Invoke-TPCollectM365Copilot.ps1  (v4.6.1)
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Collect Microsoft 365 Copilot governance posture — licensing breadth,
# sensitivity-label alignment, DLP coverage for Copilot interactions, Copilot
# Studio external-publishing exposure, and Copilot prompt/response audit retention.
#
# READ-ONLY. All Graph calls are GET. No tenant configuration is modified.
#
# Sets raw data key: 'M365Copilot'
#
# Required Graph scopes (already requested by Connect-TPServices):
#   Organization.Read.All     — /subscribedSkus
#   User.Read.All             — /users?$select=assignedLicenses
#   Policy.Read.All           — /security/dataLossPreventionPolicies (when accessible)
#   Application.Read.All      — /applications (Copilot Studio bot apps detection)
#
# Optional / fallback dependencies:
#   - IPPS session (Get-Label, Get-AutoSensitivityLabelPolicy, Get-DlpCompliancePolicy)
#     read via Get-TPRawData -Key 'Purview' to avoid duplicate API calls
#   - Get-TPRawData -Key 'AAD-AuthPolicies' for tenant-level Copilot consent settings
#
# NIST SP 800-53: AC-3 (access enforcement), AC-16 (security/privacy attributes),
#                 AU-2 (event logging), SC-28 (info-at-rest protection)
# MITRE ATT&CK:   T1530 (data from cloud storage), T1005 (data from local system),
#                 T1078 (valid accounts — Copilot license drift)
#
# Copilot service plan IDs (well-known, public Microsoft documentation):
#   0fe9c91c-7438-4cdc-9de7-9dca4ee05c93  — Microsoft 365 Copilot
#   3f30311c-6b1e-49a9-ab6c-5ab12ddcb3cf  — Copilot Studio (Power Virtual Agents)
#

function Invoke-TPCollectM365Copilot {
    [CmdletBinding()] param()

    # Well-known Copilot-conferring service plan IDs
    $copilotServicePlanIds = @(
        '0fe9c91c-7438-4cdc-9de7-9dca4ee05c93'   # Microsoft 365 Copilot
        '3f30311c-6b1e-49a9-ab6c-5ab12ddcb3cf'   # Copilot Studio
    )

    $result = [ordered]@{
        CollectorId = 'M365Copilot'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Errors      = @()
        Data        = [ordered]@{
            # Licensing
            CopilotLicensedUserCount    = 0
            TotalUserCount              = 0
            LicensedSkus                = @()

            # Sensitivity labels in Purview
            SensitivityLabelsEnabled    = $false
            SensitivityLabelCount       = 0
            AutoLabelPoliciesEnabled    = $false

            # DLP coverage for Copilot
            CopilotDLPPolicies          = @()
            CopilotDLPLocations         = @()

            # Copilot Studio external publishing
            CopilotStudioBots           = @()
            ExternalPublishingEnabled   = $false

            # Interaction data retention
            CopilotInteractionRetention = $null
            AuditCopilotEnabled         = $null   # unknown until the Exchange Online audit config is read
        }
    }

    # ── 1) Licensing: SKUs that confer Copilot ───────────────────────────────
    try {
        $skus = Invoke-TPGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' `
            -ErrorAction Stop

        $skuValues = @($skus.value ?? @())
        $copilotSkuIds = @()

        foreach ($sku in $skuValues) {
            $partNumber = [string]($sku.skuPartNumber ?? '')
            $servicePlans = @($sku.servicePlans ?? @())
            $confersCopilot = $false

            # Match by skuPartNumber prefix (e.g., "Microsoft_365_Copilot")
            # "M365_Copilot" is the documented part number of the current SKU
            # (Microsoft's licensing reference); it was not matched, so a
            # Copilot tenant read "no Copilot licenses" on every Copilot control.
            if ($partNumber -match '^(Microsoft_365_Copilot|MICROSOFT_365_COPILOT|M365_Copilot|COPILOT)') {
                $confersCopilot = $true
            }
            # Service-plan NAMES (M365_COPILOT_APPS, M365_COPILOT_BUSINESS_CHAT, ...)
            # identify every Copilot SKU variant, including EDU and add-on bundles.
            foreach ($plan in $servicePlans) {
                if ([string](Get-TPObjectField -Item $plan -Key 'servicePlanName' -Default '') -match '^M365_COPILOT_') { $confersCopilot = $true }
            }
            # Match by service plan ID — definitive
            foreach ($plan in $servicePlans) {
                $planId = [string]($plan.servicePlanId ?? '')
                if ($copilotServicePlanIds -contains $planId) {
                    $confersCopilot = $true
                }
            }

            if ($confersCopilot) {
                $copilotSkuIds += [string]$sku.skuId
                $result.Data.LicensedSkus += [ordered]@{
                    SkuId           = [string]$sku.skuId
                    SkuPartNumber   = $partNumber
                    PrepaidUnits    = [int](Get-TPNestedProperty -Object $sku -Path 'prepaidUnits.enabled' -Default 0)
                    ConsumedUnits   = [int]($sku.consumedUnits ?? 0)
                }
            }
        }

        $result.Data.CopilotLicensedUserCount = 0
        if ($result.Data.LicensedSkus.Count -gt 0) {
            # Sum consumed units across Copilot SKUs as a first-order approximation.
            # Measure-Object -Property reads members via the ETS/Get-Member adapter,
            # which does not expose Hashtable/OrderedDictionary keys (unlike the
            # PowerShell parser's own dot-access shortcut for hashtables) — piping
            # -Property ConsumedUnits over these [ordered]@{} rows throws "Cannot
            # process argument because the value of argument 'ConsumedUnits' is not
            # valid." Project the values first, then sum.
            $result.Data.CopilotLicensedUserCount = (
                $result.Data.LicensedSkus | ForEach-Object { [int]$_.ConsumedUnits } | Measure-Object -Sum
            ).Sum
        }
    } catch {
        $msg = "subscribedSkus query failed: $($_.Exception.Message)"
        $result.Errors += $msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'M365Copilot-Skus' -Message $msg
        }
    }

    # ── 2) User count + per-user license confirmation ────────────────────────
    try {
        # Every page (a tenant over 999 users read only page 1, so 1,000
        # licenses read as "999 of 999 — the entire tenant"), members only:
        # guests cannot hold Copilot, so counting them made "every member
        # licensed" read as a scoped assignment.
        $uValues = [System.Collections.Generic.List[object]]::new()
        $next = 'https://graph.microsoft.com/v1.0/users?$select=id,assignedLicenses,userType,accountEnabled&$top=999'
        $pages = 0
        while ($next -and $pages -lt 200) {
            $users = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
            foreach ($u in @(Get-TPObjectField -Item $users -Key 'value' -Default @())) { $uValues.Add($u) }
            $link = [string](Get-TPObjectField -Item $users -Key '@odata.nextLink' -Default '')
            # A nextLink identical to the page just read would loop forever.
            $next = if ($link -and $link -ne $next) { $link } else { '' }
            $pages++
        }
        $members = @($uValues | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'userType' -Default 'Member') -ne 'Guest' -and (Get-TPObjectField -Item $_ -Key 'accountEnabled' -Default $true) -ne $false })
        $result.Data.TotalUserCount = $members.Count

        # If subscribedSkus enumeration failed but per-user license data is available,
        # cross-check by counting users with a Copilot SKU assigned.
        $copilotSkuIdSet = @($result.Data.LicensedSkus | ForEach-Object { $_.SkuId })
        if ($copilotSkuIdSet.Count -gt 0) {
            $countByUser = 0
            foreach ($u in $uValues) {
                $assigned = @($u.assignedLicenses ?? @())
                foreach ($a in $assigned) {
                    if ($copilotSkuIdSet -contains [string]($a.skuId ?? '')) {
                        $countByUser += 1
                        break
                    }
                }
            }
            # Prefer per-user count when it's authoritative (avoids over-counting
            # if a single SKU appears under multiple aliases).
            if ($countByUser -gt 0) {
                $result.Data.CopilotLicensedUserCount = $countByUser
            }
        }
    } catch {
        $msg = "users query failed: $($_.Exception.Message)"
        $result.Errors += $msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'M365Copilot-Users' -Message $msg
        }
    }

    # ── 3) Sensitivity labels (prefer Purview raw-data — already collected) ──
    try {
        $purview = $null
        if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
            $purview = Get-TPRawData -Key 'Purview'
        }
        if ($purview -and $purview.Success) {
            $labels = @($purview.Data.SensitivityLabels ?? @())
            $result.Data.SensitivityLabelCount = $labels.Count
            $result.Data.SensitivityLabelsEnabled = ($labels.Count -gt 0)
        } else {
            # Fallback to Graph endpoint (v4.6.4 EMERGENCY FIX Critical #1).
            # PRIOR URL '/beta/security/labels/sensitivityLabels' was wrong (404).
            # Correct surfaces:
            #   /beta/informationProtection/policy/labels  — user-scoped labels
            #   /v1.0/security/informationProtection/sensitivityLabels — newer
            try {
                $sLabels = Invoke-TPGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/informationProtection/policy/labels' `
                    -ErrorAction Stop
                $lValues = @($sLabels.value ?? @())
                $result.Data['LabelsRead'] = $true
                $result.Data.SensitivityLabelCount = $lValues.Count
                $result.Data.SensitivityLabelsEnabled = ($lValues.Count -gt 0)
            } catch {
                $msg = "sensitivityLabels query inaccessible: $($_.Exception.Message)"
                $result.Errors += $msg
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'M365Copilot-Labels' -Message $msg
                }
            }
        }

        # Auto-label policies — best-effort via IPPS cmdlet if available
        if (Get-Command Get-AutoSensitivityLabelPolicy -ErrorAction SilentlyContinue) {
            try {
                $auto = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
                $result.Data.AutoLabelPoliciesEnabled = (
                    # Simulation modes (TestWithNotifications / TestWithoutNotifications)
                    # label nothing: only Mode 'Enable' is enforcement.
                    @($auto | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Mode' -Default '') -eq 'Enable' }).Count -gt 0
                )
            } catch {
                $result.Errors += "AutoLabelPolicy query failed: $($_.Exception.Message)"
            }
        }
    } catch {
        $result.Errors += "Label collection error: $($_.Exception.Message)"
    }

    # ── 4) DLP coverage for Copilot ───────────────────────────────────────────
    try {
        $purview = $null
        if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
            $purview = Get-TPRawData -Key 'Purview'
        }

        $copilotDlpFromPurview = @()
        if ($purview -and $purview.Success) {
            $dlp = @($purview.Data.DLPPolicies ?? @())
            foreach ($p in $dlp) {
                $workloads = @($p.Workloads ?? @())
                # Whole word only: 'AI' matched "Mail", "Email", "Retain"...
                $nameMatchesCopilot = ([string]$p.Name) -match '\bCopilot\b'
                $workloadMatchesCopilot = ($workloads -contains 'Copilot') -or
                                          ($workloads -contains 'M365Copilot') -or
                                          ($workloads -contains 'CopilotExperiences') -or
                                          ($workloads -contains 'Applications')   # the Microsoft 365 Copilot location

                if ($workloadMatchesCopilot -or $nameMatchesCopilot) {
                    $copilotDlpFromPurview += [ordered]@{
                        Name      = [string]$p.Name
                        Enabled   = [bool]$p.Enabled
                        Workloads = $workloads
                        Source    = 'Purview-IPPS'
                    }
                    foreach ($w in $workloads) {
                        if ($w -and ($result.Data.CopilotDLPLocations -notcontains $w)) {
                            $result.Data.CopilotDLPLocations += [string]$w
                        }
                    }
                }
            }
        }

        # v4.6.4 EMERGENCY FIX (Critical #1): The Graph DLP fallback endpoint
        # '/beta/security/dataLossPreventionPolicies' does not exist as a
        # readable resource — DLP compliance policies are NOT exposed through
        # Graph today. The authoritative source is Get-DlpCompliancePolicy
        # over an IPP session, already collected by the Purview collector.
        # If the Purview pass produced nothing, downstream evaluators must
        # route to NotApplicable rather than relying on a fake fallback that
        # would silently leave CopilotDLPPolicies empty without surfacing a
        # collection failure. Therefore: no Graph fallback. If $purview was
        # absent or unsuccessful, record an explicit Errors entry so the
        # evaluator and HTML report can show the gap honestly.
        if (-not ($purview -and $purview.Success)) {
            $result.Errors += 'Copilot DLP requires Purview/IPPS session (Get-DlpCompliancePolicy); no Graph fallback exists.'
        }

        $result.Data.CopilotDLPPolicies = $copilotDlpFromPurview
    } catch {
        $result.Errors += "DLP collection error: $($_.Exception.Message)"
    }

    # ── 5) Copilot Studio bots — external publishing ─────────────────────────
    # Power Platform admin endpoints are not in standard Graph. We probe
    # /applications for known Copilot Studio bot publisher patterns. If nothing
    # is found, downstream evaluator routes to NotApplicable.
    try {
        $apps = Invoke-TPGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,publisherDomain,tags&`$top=200" `
            -ErrorAction Stop
        $aValues = @($apps.value ?? @())

        $studioBots = @()
        foreach ($app in $aValues) {
            $dn = [string]($app.displayName ?? '')
            $tags = @($app.tags ?? @())
            $isCopilotStudio = ($dn -match 'Copilot Studio|Power Virtual Agent|PVA') -or
                               ($tags -contains 'CopilotStudio') -or
                               ($tags -contains 'PowerVirtualAgents')

            if ($isCopilotStudio) {
                # External publishing state is not directly readable from
                # /applications — record the bot's presence and mark
                # PublishingState 'unknown' so the evaluator can flag for
                # manual confirmation.
                $studioBots += [ordered]@{
                    Name             = $dn
                    AppId            = [string]$app.id
                    PublisherDomain  = [string]($app.publisherDomain ?? '')
                    ExternalChannels = @()
                    PublishingState  = 'unknown'
                }
            }
        }

        $result.Data.CopilotStudioBots = $studioBots
        # Without Power Platform admin API access, we cannot definitively
        # determine ExternalPublishingEnabled. Leave $false unless a bot
        # with a non-internal publisher domain is detected.
        $externalDetected = @($studioBots | Where-Object {
            $_.PublisherDomain -and $_.PublisherDomain -notmatch 'onmicrosoft\.com$'
        }).Count -gt 0
        $result.Data.ExternalPublishingEnabled = $externalDetected
    } catch {
        $msg = "Copilot Studio enumeration inaccessible: $($_.Exception.Message)"
        $result.Errors += $msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'M365Copilot-Studio' -Message $msg
        }
    }

    # ── 6) Audit retention for Copilot interactions ──────────────────────────
    try {
        $purview = $null
        if (Get-Command Get-TPRawData -ErrorAction SilentlyContinue) {
            $purview = Get-TPRawData -Key 'Purview'
        }
        if ($purview -and $purview.Success) {
            $auditCfg = $purview.Data.AuditConfig
            if ($auditCfg) {
                # A False read anywhere but the Exchange Online session is not
                # evidence (Security & Compliance always reports False) — record
                # it as unknown ($null) so PPL-3.5 does not score a false Gap.
                $ualOn  = [bool](Get-TPObjectField -Item $auditCfg -Key 'UnifiedAuditLogIngestionEnabled' -Default $false)
                $ualSrc = [string](Get-TPObjectField -Item $auditCfg -Key 'Source' -Default 'Unknown')
                $result.Data.AuditCopilotEnabled = if ($ualOn) { $true } elseif ($ualSrc -eq 'ExchangeOnline') { $false } else { $null }
            }

            # Retention policies covering Copilot interactions
            $retention = @($purview.Data.RetentionPolicies ?? @())
            $copilotRet = @($retention | Where-Object {
                $wls = @($_.Workloads ?? @())
                ($wls -contains 'Copilot') -or
                ($wls -contains 'M365Copilot') -or
                ([string]$_.Name -match '\bCopilot\b')
            })
            if ($copilotRet.Count -gt 0) {
                $result.Data.CopilotInteractionRetention = 'policy-defined'
            } else {
                $result.Data.CopilotInteractionRetention = $null
            }
        }
    } catch {
        $result.Errors += "Audit/retention collection error: $($_.Exception.Message)"
    }

    # ── Finalize ─────────────────────────────────────────────────────────────
    # Success requires at least ONE primary data source to have completed.
    # Primary sources:
    #   - subscribedSkus (licensing): populates LicensedSkus
    #   - users enumeration: populates TotalUserCount
    # Supplemental sources (sensitivity labels, DLP, Copilot Studio apps,
    # interaction retention) are best-effort — their failure must NOT mask
    # a completely dead collector as live. The prior `Errors.Count -lt 6`
    # heuristic would have reported Success=$true when every single endpoint
    # failed (since failures-required-to-trip was strictly greater-than-equal
    # to 6, and we only emit six error categories), turning zero-data into
    # an apparent "everything's compliant" reading downstream.
    $licensingOk = ($result.Data.LicensedSkus.Count -gt 0)
    $usersOk     = ($result.Data.TotalUserCount -gt 0)
    $result.Success = ($licensingOk -or $usersOk)

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'M365Copilot' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        if ($result.Success) {
            $note = if ($result.Errors.Count -gt 0) { "Partial: $($result.Errors.Count) endpoint error(s)" } else { '' }
            $status = if ($result.Errors.Count -gt 0) { 'Partial' } else { 'Collected' }
            Register-TPCoverage -Family 'M365Copilot' -Status $status -Note $note
        } else {
            Register-TPCoverage -Family 'M365Copilot' -Status 'Failed' -Note ($result.Errors -join '; ')
        }
    }

    return $result
}

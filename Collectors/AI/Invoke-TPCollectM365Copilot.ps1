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
# Sets raw data key: 'M365Copilot'. Data.SectionStatus records the Licensing
# (subscribedSkus) and Users (user enumeration) reads; Data.LicensingMeasurements
# holds each seat count with its availability, source and completeness
# (Lib/Get-TPCopilotLicensingState.ps1). The other sections (labels, DLP,
# Copilot Studio name match, audit) do not publish a status yet.
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

    # Source and note of each licensing measurement, kept here so a measurement
    # is rebuilt without reading back into the result's own nested fields.
    $srcRecognized      = 'subscribedSkus (SKUs this tool recognizes as Copilot)'
    $srcPurchased       = 'subscribedSkus.prepaidUnits.enabled, summed over the recognized SKUs'
    $srcConsumed        = 'subscribedSkus.consumedUnits, summed over the recognized SKUs'
    $noteConsumed       = 'Per-SKU assignments: an account holding two recognized SKUs counts twice. Not a unique-user count, and assignments are not usage.'
    $srcEnabled         = 'users (enabled, userType not Guest)'
    $srcAssigned        = 'users.assignedLicenses (any account holding a recognized SKU)'
    $srcAssignedMembers = 'users.assignedLicenses (enabled members holding a recognized SKU)'
    $noteAssigned       = 'Assignments are not usage.'

    $result = [ordered]@{
        CollectorId = 'M365Copilot'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Errors      = @()
        Data        = [ordered]@{
            # Licensing (D1, 2026-11-06). Each read records its outcome, and every
            # count is a measurement with its availability, source and completeness
            # (Lib/Get-TPCopilotLicensingState.ps1). A value that was not read stays
            # $null: a default zero is not evidence of a successful read.
            SectionStatus               = [ordered]@{ Licensing = 'NotRun'; Users = 'NotRun' }
            SectionErrors               = [ordered]@{}
            LicensingMeasurements       = [ordered]@{
                RecognizedSkuCount     = (New-TPCopilotMeasurement -Kind 'RecognizedProducts' -Source $srcRecognized)
                PurchasedSeats         = (New-TPCopilotMeasurement -Kind 'PurchasedCapacity' -Source $srcPurchased)
                SkuConsumedUnits       = (New-TPCopilotMeasurement -Kind 'SkuAssignments' -Source $srcConsumed -Note $noteConsumed)
                EnabledMembers         = (New-TPCopilotMeasurement -Kind 'EnumeratedAccounts' -Source $srcEnabled)
                AssignedUsers          = (New-TPCopilotMeasurement -Kind 'UniqueAssignedAccounts' -Source $srcAssigned -Note $noteAssigned)
                AssignedEnabledMembers = (New-TPCopilotMeasurement -Kind 'UniqueAssignedAccounts' -Source $srcAssignedMembers -Note $noteAssigned)
            }
            UserEnumeration             = [ordered]@{ PagesRead = 0; PageCap = 200; StopReason = 'NotRun'; RowsRead = $null; DistinctAccounts = $null; DuplicateRows = $null; RowsWithoutId = $null; AccountEnabledUnknown = $null }
            # Kept for older readers. CopilotLicensedUserCount is the number of unique
            # accounts holding a recognized Copilot SKU and TotalUserCount the enabled
            # members, each set only from a COMPLETE user enumeration and $null
            # otherwise (both used to start at 0 and keep it when a read failed, and
            # the first could also hold summed consumed units).
            CopilotLicensedUserCount    = $null
            TotalUserCount              = $null
            LicensedSkus                = @()

            # Sensitivity labels in Purview
            SensitivityLabelsEnabled    = $false
            SensitivityLabelCount       = 0
            AutoLabelPoliciesEnabled    = $false
            # $true once Get-AutoSensitivityLabelPolicy was read and each policy's Enabled flag
            # judged beside its Mode; $false when the read did not happen or failed.
            AutoLabelPoliciesRead       = $false

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
    $recognizedSkuIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $skus = Invoke-TPGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' `
            -ErrorAction Stop

        $skuValues = @(@(Get-TPObjectField -Item $skus -Key 'value' -Default @()) | Where-Object { $null -ne $_ })

        foreach ($sku in $skuValues) {
            $partNumber = [string](Get-TPObjectField -Item $sku -Key 'skuPartNumber' -Default '')
            $servicePlans = @(@(Get-TPObjectField -Item $sku -Key 'servicePlans' -Default @()) | Where-Object { $null -ne $_ })
            $confersCopilot = $false

            # Match by skuPartNumber prefix (e.g., "Microsoft_365_Copilot")
            # "M365_Copilot" is the documented part number of the current SKU
            # (Microsoft's licensing reference); it was not matched, so a
            # Copilot tenant read "no Copilot licenses" on every Copilot control.
            # The list is this tool's recognition rule, not Microsoft's catalog:
            # a SKU it does not know reads as "no recognized SKU", never "no Copilot".
            if ($partNumber -match (Get-TPCopilotSkuPartNumberPattern)) {
                $confersCopilot = $true
            }
            # Service-plan NAMES (M365_COPILOT_APPS, M365_COPILOT_BUSINESS_CHAT, ...)
            # identify every Copilot SKU variant, including EDU and add-on bundles.
            foreach ($plan in $servicePlans) {
                if ([string](Get-TPObjectField -Item $plan -Key 'servicePlanName' -Default '') -match '^M365_COPILOT_') { $confersCopilot = $true }
            }
            # Match by service plan ID — definitive
            foreach ($plan in $servicePlans) {
                $planId = [string](Get-TPObjectField -Item $plan -Key 'servicePlanId' -Default '')
                if ($copilotServicePlanIds -contains $planId) {
                    $confersCopilot = $true
                }
            }

            if ($confersCopilot) {
                $skuId = [string](Get-TPObjectField -Item $sku -Key 'skuId' -Default '')
                if ($skuId) { [void]$recognizedSkuIds.Add($skuId) }
                # Each value as returned, or $null when absent or not a whole number.
                $result.Data.LicensedSkus += [ordered]@{
                    SkuId           = $skuId
                    SkuPartNumber   = $partNumber
                    PrepaidUnits    = (ConvertTo-TPCopilotCount (Get-TPNestedProperty -Object $sku -Path 'prepaidUnits.enabled' -Default $null))
                    ConsumedUnits   = (ConvertTo-TPCopilotCount (Get-TPObjectField -Item $sku -Key 'consumedUnits' -Default $null))
                }
            }
        }

        $rows = @($result.Data.LicensedSkus)
        $m = $result.Data.LicensingMeasurements
        $m.RecognizedSkuCount = New-TPCopilotMeasurement -Kind 'RecognizedProducts' -Source $srcRecognized -Value $rows.Count -Completeness 'Complete'
        # A sum is complete only when every recognized SKU returned its value.
        $prepaid  = @($rows | ForEach-Object { $_.PrepaidUnits })
        $consumed = @($rows | ForEach-Object { $_.ConsumedUnits })
        $sumOf = { param($vals) $t = 0; foreach ($v in $vals) { if ($null -ne $v) { $t += [int]$v } }; $t }
        if (@($prepaid | Where-Object { $null -eq $_ }).Count -eq 0) {
            $m.PurchasedSeats = New-TPCopilotMeasurement -Kind 'PurchasedCapacity' -Source $srcPurchased -Value (& $sumOf $prepaid) -Completeness 'Complete'
        } elseif (@($prepaid | Where-Object { $null -ne $_ }).Count -gt 0) {
            $m.PurchasedSeats = New-TPCopilotMeasurement -Kind 'PurchasedCapacity' -Source $srcPurchased -Value (& $sumOf $prepaid) -Completeness 'Incomplete' -Note 'At least one recognized SKU did not return prepaidUnits.enabled.'
        }
        if (@($consumed | Where-Object { $null -eq $_ }).Count -eq 0) {
            $m.SkuConsumedUnits = New-TPCopilotMeasurement -Kind 'SkuAssignments' -Source $srcConsumed -Value (& $sumOf $consumed) -Completeness 'Complete' -Note $noteConsumed
        } elseif (@($consumed | Where-Object { $null -ne $_ }).Count -gt 0) {
            $m.SkuConsumedUnits = New-TPCopilotMeasurement -Kind 'SkuAssignments' -Source $srcConsumed -Value (& $sumOf $consumed) -Completeness 'Incomplete' -Note ($noteConsumed + ' At least one recognized SKU did not return consumedUnits.')
        }
        $result.Data.SectionStatus.Licensing = 'Collected'
    } catch {
        $msg = "subscribedSkus query failed: $($_.Exception.Message)"
        $result.Errors += $msg
        $result.Data.SectionStatus.Licensing = 'Failed'
        $result.Data.SectionErrors['Licensing'] = $msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'M365Copilot-Skus' -Message $msg
        }
    }

    # ── 2) User enumeration + per-user license confirmation ──────────────────
    # Every page (a tenant over 999 users read only page 1, so 1,000 licenses
    # read as "999 of 999 — the entire tenant"), members only for the
    # denominator: guests cannot hold Copilot, so counting them made "every
    # member licensed" read as a scoped assignment. Rows read before a failure
    # are kept and marked incomplete, never presented as the whole tenant.
    $uValues = [System.Collections.Generic.List[object]]::new()
    $enum = $result.Data.UserEnumeration
    $usersStatus = 'NotRun'
    try {
        $next = 'https://graph.microsoft.com/v1.0/users?$select=id,assignedLicenses,userType,accountEnabled&$top=999'
        $pages = 0
        $stop = 'Complete'
        while ($next) {
            if ($pages -ge $enum.PageCap) { $stop = 'PageCap'; break }
            $users = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
            foreach ($u in @(@(Get-TPObjectField -Item $users -Key 'value' -Default @()) | Where-Object { $null -ne $_ })) { $uValues.Add($u) }
            $pages++
            $enum.PagesRead = $pages
            $link = [string](Get-TPObjectField -Item $users -Key '@odata.nextLink' -Default '')
            # A nextLink identical to the page just read would loop forever; the
            # rest of the list was not read, so the enumeration is incomplete.
            if ($link -and $link -eq $next) { $stop = 'RepeatedNextLink'; break }
            $next = $link
        }
        $enum.StopReason = $stop
        $usersStatus = if ($stop -eq 'Complete') { 'Collected' } else { 'Truncated' }
        if ($usersStatus -eq 'Truncated') {
            $why = if ($stop -eq 'PageCap') { "users enumeration stopped at the page cap ($($enum.PageCap) pages); the rest of the directory was not read" } else { 'users enumeration stopped: Graph returned the same next link twice; the rest of the directory was not read' }
            $result.Errors += $why
            $result.Data.SectionErrors['Users'] = $why
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'M365Copilot-Users' -Message $why
            }
        }
    } catch {
        $msg = "users query failed: $($_.Exception.Message)"
        if ($uValues.Count -gt 0) { $msg += " (after $($uValues.Count) account(s) on $($enum.PagesRead) page(s) were read; those are kept as an incomplete count)" }
        $result.Errors += $msg
        $usersStatus = 'Failed'
        $enum.StopReason = 'Failed'
        $result.Data.SectionErrors['Users'] = $msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'M365Copilot-Users' -Message $msg
        }
    }
    $result.Data.SectionStatus.Users = $usersStatus

    if ($usersStatus -ne 'NotRun' -and ($usersStatus -ne 'Failed' -or $uValues.Count -gt 0)) {
        $complete = ($usersStatus -eq 'Collected')

        # Accounts are counted once each, by object id: a row Graph repeats is one
        # account, and a row with no id cannot be told apart from the others, so it
        # is left out and every count it could belong to is incomplete.
        $byId = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::OrdinalIgnoreCase)
        $noId = 0; $dupes = 0
        foreach ($u in $uValues) {
            $id = ([string](Get-TPObjectField -Item $u -Key 'id' -Default '')).Trim()
            if (-not $id) { $noId++; continue }
            if ($byId.Contains($id)) { $dupes++; continue }
            $byId[$id] = $u
        }
        $accounts = @($byId.Values)

        # Enabled member: accountEnabled read as $true and userType not Guest (an
        # absent userType is a member account, as Graph documents for older
        # accounts). An account whose accountEnabled was not returned as a boolean
        # cannot be placed in or out of the population, so it is left out and the
        # member counts are incomplete; it is never assumed enabled.
        $unknownEnabled = 0
        $members = [System.Collections.Generic.List[object]]::new()
        foreach ($u in $accounts) {
            $enabled = Get-TPObjectField -Item $u -Key 'accountEnabled' -Default $null
            if ($enabled -isnot [bool]) { $unknownEnabled++; continue }
            if ($enabled -and [string](Get-TPObjectField -Item $u -Key 'userType' -Default 'Member') -ne 'Guest') { $members.Add($u) }
        }
        $memberIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($u in $members) { [void]$memberIds.Add([string](Get-TPObjectField -Item $u -Key 'id' -Default '')) }

        $enum.RowsRead           = $uValues.Count
        $enum.DistinctAccounts   = $accounts.Count
        $enum.DuplicateRows      = $dupes
        $enum.RowsWithoutId      = $noId
        $enum.AccountEnabledUnknown = $unknownEnabled

        $accountsComplete = ($complete -and $noId -eq 0)
        $membersComplete  = ($accountsComplete -and $unknownEnabled -eq 0)
        $accountsCompleteness = if ($accountsComplete) { 'Complete' } else { 'Incomplete' }
        $membersCompleteness  = if ($membersComplete) { 'Complete' } else { 'Incomplete' }
        $why = @()
        if ($noId -gt 0) { $why += "$noId row(s) carried no account id and were left out" }
        if ($unknownEnabled -gt 0) { $why += "$unknownEnabled account(s) did not return accountEnabled and were left out of the member counts" }
        $whyNote = if ($why.Count) { ' ' + ($why -join '; ') + '.' } else { '' }

        $m = $result.Data.LicensingMeasurements
        $m.EnabledMembers = New-TPCopilotMeasurement -Kind 'EnumeratedAccounts' -Source $srcEnabled -Value $members.Count -Completeness $membersCompleteness -Note ($whyNote.Trim())
        if ($membersComplete) { $result.Data.TotalUserCount = $members.Count }

        # Holders can be counted only against a known set of recognized SKUs,
        # i.e. when the subscription list was read. An account holding two
        # recognized SKUs is one holder.
        if ($result.Data.SectionStatus.Licensing -eq 'Collected') {
            $holds = { param($u)
                foreach ($a in @(@(Get-TPObjectField -Item $u -Key 'assignedLicenses' -Default @()) | Where-Object { $null -ne $_ })) {
                    if ($recognizedSkuIds.Contains([string](Get-TPObjectField -Item $a -Key 'skuId' -Default ''))) { return $true }
                }
                return $false
            }
            $holders = @($accounts | Where-Object { & $holds $_ })
            $memberHolders = @($holders | Where-Object { $memberIds.Contains([string](Get-TPObjectField -Item $_ -Key 'id' -Default '')) })
            $m.AssignedUsers = New-TPCopilotMeasurement -Kind 'UniqueAssignedAccounts' -Source $srcAssigned -Value $holders.Count -Completeness $accountsCompleteness -Note (($noteAssigned + $whyNote).Trim())
            $m.AssignedEnabledMembers = New-TPCopilotMeasurement -Kind 'UniqueAssignedAccounts' -Source $srcAssignedMembers -Value $memberHolders.Count -Completeness $membersCompleteness -Note (($noteAssigned + $whyNote).Trim())
            if ($accountsComplete) { $result.Data.CopilotLicensedUserCount = $holders.Count }
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
                    # label nothing: only Mode 'Enable' is enforcement, and Enabled is a
                    # separate switch (Set-AutoSensitivityLabelPolicy -Enabled), so a
                    # Mode-Enable policy that is turned off labels nothing either.
                    @($auto | Where-Object { $_ -and [string](Get-TPObjectField -Item $_ -Key 'Mode' -Default '') -eq 'Enable' -and (Get-TPObjectField -Item $_ -Key 'Enabled' -Default $null) -eq $true }).Count -gt 0
                )
                $result.Data.AutoLabelPoliciesRead = $true
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
    #   - subscribedSkus (licensing): SectionStatus.Licensing
    #   - users enumeration: SectionStatus.Users (Truncated still yields usable,
    #     incomplete evidence)
    # Supplemental sources (sensitivity labels, DLP, Copilot Studio apps,
    # interaction retention) are best-effort — their failure must NOT mask
    # a completely dead collector as live. The prior `Errors.Count -lt 6`
    # heuristic would have reported Success=$true when every single endpoint
    # failed (since failures-required-to-trip was strictly greater-than-equal
    # to 6, and we only emit six error categories), turning zero-data into
    # an apparent "everything's compliant" reading downstream.
    # Read from the recorded outcomes, never from a count (a tenant with no
    # recognized Copilot SKU is a successful read). Success says the collector
    # produced usable evidence; it is not a statement that coverage is complete,
    # which the coverage status and SectionStatus carry.
    $licensingOk = ($result.Data.SectionStatus.Licensing -eq 'Collected')
    $usersOk     = ($result.Data.SectionStatus.Users -in @('Collected', 'Truncated'))
    $result.Success = ($licensingOk -or $usersOk)

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'M365Copilot' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        if ($result.Success) {
            # A truncated or failed licensing or user read is incomplete coverage
            # even when no other endpoint failed.
            $incomplete = @(@('Licensing', 'Users') | Where-Object { $result.Data.SectionStatus[$_] -ne 'Collected' })
            $note = if ($result.Errors.Count -gt 0 -or $incomplete.Count -gt 0) {
                (@(if ($incomplete.Count -gt 0) { "Incomplete: $(@($incomplete | ForEach-Object { "$_ $($result.Data.SectionStatus[$_])" }) -join ', ')" }) +
                 @(if ($result.Errors.Count -gt 0) { "$($result.Errors.Count) endpoint error(s)" })) -join '; '
            } else { '' }
            $status = if ($result.Errors.Count -gt 0 -or $incomplete.Count -gt 0) { 'Partial' } else { 'Collected' }
            Register-TPCoverage -Family 'M365Copilot' -Status $status -Note $note
        } else {
            Register-TPCoverage -Family 'M365Copilot' -Status 'Failed' -Note ($result.Errors -join '; ')
        }
    }

    return $result
}

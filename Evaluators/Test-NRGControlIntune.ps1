#Requires -Version 7.0
#
# Test-NRGControlIntune.ps1
# Evaluates Intune controls. Reads from the three split raw-data keys produced by
# Invoke-NRGCollectIntuneEndpointSecurity / DeviceCompliance / AppProtection.
#
# Controls: INT-1.1 through INT-4.4 (17 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#

function Test-NRGControlIntune {
    [CmdletBinding()] param()
    $es  = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    $dc  = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    $app = Get-NRGRawData -Key 'Intune-AppProtection'

    $anySuccess = ($es -and $es.Success) -or ($dc -and $dc.Success) -or ($app -and $app.Success)
    if (-not $anySuccess) {
        foreach ($cid in @('INT-1.1','INT-1.2','INT-1.3','INT-1.4','INT-1.5')) {
            $c = Get-NRGControlById -ControlId $cid
            if ($c) {
                Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Endpoint' -Title $c.Title `
                    -Detail 'Intune collectors did not run.'
            }
        }
        return
    }

    # Merge fields the legacy ITN-1.x checks expect into a single $d view.
    #
    # Two traps live in this merge and both produced false passes.
    #
    #   @($null).Count is 1, not 0. A section the collector never populated
    #   came back $null, was wrapped by @(...) downstream into a one-element
    #   array containing $null, and INT-1.1 reported "1 compliance policies
    #   active — Satisfied" on a tenant where the query had simply failed.
    #   Nulls are stripped here so an absent section counts 0.
    #
    #   `$x = if (...) { ... } else { @() }` assigns $null, because the
    #   if-block enumerates the empty array away. Built with an explicit
    #   helper instead.
    $pick = {
        param($raw, [string]$section)
        if (-not $raw -or -not $raw.Success) { return @() }
        return @($raw.Data[$section] | Where-Object { $null -ne $_ })
    }
    # Which sections can be trusted as evidence. A section whose sub-query
    # failed is an unknown, and a control that depends on it must say so
    # rather than reading the resulting emptiness as compliance.
    $collected = @{
        CompliancePolicies       = (Test-NRGSectionCollected $dc  'CompliancePolicies')
        ConfigurationProfiles    = (Test-NRGSectionCollected $dc  'ConfigurationProfiles')
        AppProtectionPolicies    = (Test-NRGSectionCollected $app 'AppProtectionPolicies')
        EnrollmentConfig         = (Test-NRGSectionCollected $dc  'EnrollmentConfig')
        EndpointSecurityPolicies = (Test-NRGSectionCollected $es  'EndpointSecurityPolicies')
    }
    $d = @{
        CompliancePolicies       = & $pick $dc  'CompliancePolicies'
        ConfigurationProfiles    = & $pick $dc  'ConfigurationProfiles'
        AppProtectionPolicies    = & $pick $app 'AppProtectionPolicies'
        EnrollmentConfig         = & $pick $dc  'EnrollmentConfig'
        EndpointSecurityPolicies = & $pick $es  'EndpointSecurityPolicies'
    }

    $cit = { param($id) Get-NRGFrameworkCitations -ControlId $id }

    # ITN-1.1 — Device compliance policies, counting only ASSIGNED ones: an
    # unassigned policy evaluates no device.
    $c = Get-NRGControlById -ControlId 'INT-1.1'
    if ($c -and -not $collected['CompliancePolicies']) {
        Add-NRGFinding -ControlId 'INT-1.1' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') -Detail 'CompliancePolicies was not collected; not assessed.'
    } elseif ($c) {
        $all = @($d.CompliancePolicies)
        $assigned = @(Select-NRGAssignedPolicies $all)
        if ($assigned.Count -gt 0) {
            # The expected state is an assigned compliance policy PER enrolled platform,
            # each with a non-compliance action. One assigned policy covers one platform,
            # not the fleet, so coverage is judged per platform from the enrolled-device
            # counts; the non-compliance action is not read, so it is never credited.
            $plats = @(
                @{ Name = 'Windows'; Device = '^Windows';     Policy = '(?i)windows' }
                @{ Name = 'iOS/iPadOS'; Device = '^(iOS|iPadOS)'; Policy = '(?i)\bios|ipados' }
                @{ Name = 'Android'; Device = '^Android';     Policy = '(?i)android' }
                @{ Name = 'macOS'; Device = '^macOS';         Policy = '(?i)macos' }
            )
            $unread = $null -eq (Get-NRGEnrolledPlatformCount -Raw $dc -Pattern '.')
            $covered = @(); $uncovered = @()
            if (-not $unread) {
                foreach ($pl in $plats) {
                    $n = [int](Get-NRGEnrolledPlatformCount -Raw $dc -Pattern $pl.Device)
                    if ($n -le 0) { continue }
                    $has = @($assigned | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Platform' -Default '') -match $pl.Policy }).Count -gt 0
                    if ($has) { $covered += "$($pl.Name) ($n device(s))" } else { $uncovered += "$($pl.Name) ($n device(s))" }
                }
            }
            $verified = "Verified: $($assigned.Count) assigned compliance policy(ies)."
            if ($unread) {
                Add-NRGFinding -ControlId 'INT-1.1' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified Not assessed: whether every enrolled platform has one, because the enrolled-device platform counts were not read; and each policy's non-compliance action is not read." `
                    -CurrentValue "$($assigned.Count) assigned compliance policy(ies); platform coverage not read" -RequiredValue 'An assigned compliance policy per enrolled platform, each with a non-compliance action'
            } elseif ($uncovered.Count -gt 0) {
                Add-NRGFinding -ControlId 'INT-1.1' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified$(if ($covered.Count) { " Covered: $($covered -join ', ')." }) Shortfall: no assigned compliance policy for $($uncovered -join ', '), so those devices are not held to any baseline." `
                    -CurrentValue "Covered: $($covered -join ', '); not covered: $($uncovered -join ', ')" -RequiredValue 'An assigned compliance policy per enrolled platform, each with a non-compliance action' -Remediation $c.Remediation
            } else {
                Add-NRGFinding -ControlId 'INT-1.1' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified Every enrolled platform has an assigned compliance policy ($($covered -join ', ')). Not assessed: each policy's non-compliance action; it is not read, so the action half of the requirement is not established." `
                    -CurrentValue "Platforms covered: $($covered -join ', '); non-compliance action not read" -RequiredValue 'An assigned compliance policy per enrolled platform, each with a non-compliance action'
            }
        } else {
            $why = if ($all.Count) { "$($all.Count) compliance policy(ies) exist but none is assigned to any user or device." } else { 'No device compliance policies configured.' }
            Add-NRGFinding -ControlId 'INT-1.1' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.1') `
                -Detail "$why Devices no policy evaluates are not held to any baseline." `
                -CurrentValue 'No assigned compliance policies' -RequiredValue 'At least one assigned compliance policy' -Remediation $c.Remediation
        }
    }

    # INT-1.2 — Non-compliant device access blocked via Conditional Access.
    # It read "any configuration profile exists" (a Wi-Fi profile passed). The
    # control is a CA policy requiring a compliant (or hybrid-joined) device.
    $c = Get-NRGControlById -ControlId 'INT-1.2'
    # While Security Defaults is enabled no CA policy can be turned on, and it
    # has no device-compliance requirement of its own: a Gap, and a report-only
    # compliant-device policy beside it earns nothing (same as AAD-2.3).
    if ($c -and (Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId 'INT-1.2' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.2') -State 'Gap' -Severity $c.Severity `
            -Detail 'No policy in force requires a compliant device: Security Defaults has no device-compliance requirement, so a device Intune marks non-compliant (or one never enrolled) still reaches Microsoft 365.' `
            -CurrentValue 'Security Defaults enabled; no compliant-device requirement in force' `
            -RequiredValue 'Enabled CA policy requiring a compliant device for all users on all cloud apps' `
            -Remediation $c.Remediation -NeedsConditionalAccess
    } elseif ($c) {
        $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
        if (-not $ca -or -not $ca.Success) {
            Add-NRGFinding -ControlId 'INT-1.2' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.2') -Detail 'Conditional Access policies were not collected; not assessed.'
        } else {
            $device = @('compliantDevice','domainJoinedDevice')
            $pols = @(Get-NRGObjectField -Item $ca.Data -Key 'Policies' -Default @() | Where-Object { $null -ne $_ })
            $asks = @($pols | Where-Object { @((Get-NRGCAGrantAlternatives -Policy $_).Controls) -contains 'compliantDevice' -and
                [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -in @('enabled','enabledForReportingButNotEnforced') })
            $full = @($asks | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' -and
                (Test-NRGCAAllUsers $_) -and (Test-NRGCAAllApps $_) -and (Test-NRGCAGrantRequires -Policy $_ -Any $device) })
            $names = { param($l) (@($l) | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '?') }) -join ', ' }
            if ($full.Count -gt 0) {
                Add-NRGFinding -ControlId 'INT-1.2' -State 'Satisfied' -Category 'Endpoint' -Title $c.Title -Severity 'Informational' -FrameworkIds (& $cit 'INT-1.2') `
                    -Detail "A compliant (or hybrid-joined) device is required for all users on all cloud apps: $(& $names $full)."
            } elseif ($asks.Count -gt 0) {
                Add-NRGFinding -ControlId 'INT-1.2' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.2') `
                    -Detail "Conditional Access asks for a compliant device, but not of every user on every app, or only in report-only mode, or as one alternative among others: $(& $names $asks)." `
                    -RequiredValue 'Enabled CA policy requiring a compliant device for all users on all cloud apps' -Remediation $c.Remediation
            } else {
                Add-NRGFinding -ControlId 'INT-1.2' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.2') `
                    -Detail 'No Conditional Access policy requires a compliant device, so a device Intune marks non-compliant (or one never enrolled) still reaches Microsoft 365.' `
                    -RequiredValue 'Enabled CA policy requiring a compliant device for all users on all cloud apps' -Remediation $c.Remediation
            }
        }
    }

    # INT-1.3 — Windows compliance policy requires encryption: BitLocker via
    # Device Health Attestation (bitLockerEnabled) or "Encryption of data
    # storage on device" (storageRequireEncryption).
    $c = Get-NRGControlById -ControlId 'INT-1.3'
    if ($c -and -not $collected['CompliancePolicies']) {
        Add-NRGFinding -ControlId 'INT-1.3' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.3') -Detail 'CompliancePolicies was not collected; not assessed.'
    } elseif ($c) {
        $winPolicies = @(Select-NRGAssignedPolicies @($d.CompliancePolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Platform') -match 'windows10|Windows' }))
        $enc = @($winPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'BitLockerEnabled') -eq $true -or (Get-NRGObjectField -Item $_ -Key 'StorageRequireEncryption') -eq $true })
        if ($winPolicies.Count -eq 0) {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.3') `
                -Detail 'No assigned Windows compliance policy exists, so no Windows device is required to be encrypted.' -RequiredValue 'Require BitLocker / storage encryption in an assigned Windows compliance policy' -Remediation $c.Remediation
        } elseif ($enc.Count -eq $winPolicies.Count) {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'Satisfied' -Category 'Endpoint' -Title $c.Title -Severity 'Informational' -FrameworkIds (& $cit 'INT-1.3') `
                -Detail "Every assigned Windows compliance policy ($($winPolicies.Count)) requires encryption."
        } elseif ($enc.Count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.3') `
                -Detail "$($enc.Count) of $($winPolicies.Count) assigned Windows compliance policies require encryption; devices under the others are not required to be encrypted." -Remediation $c.Remediation
        } else {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.3') `
                -Detail 'No assigned Windows compliance policy requires encryption. Unencrypted devices can access corporate data.' `
                -CurrentValue "Encryption not required in $($winPolicies.Count) Windows policy(ies)" -RequiredValue 'Require BitLocker / storage encryption' -Remediation $c.Remediation
        }
    }

    # INT-1.4 — App protection (MAM) policies for iOS and Android. App
    # CONFIGURATION policies (also returned by managedAppPolicies) protect
    # nothing and are no longer counted.
    $c = Get-NRGControlById -ControlId 'INT-1.4'
    if ($c -and -not $collected['AppProtectionPolicies']) {
        Add-NRGFinding -ControlId 'INT-1.4' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.4') -Detail 'AppProtectionPolicies was not collected; not assessed.'
    } elseif ($c) {
        $prot = @(Select-NRGAssignedPolicies @($d.AppProtectionPolicies | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Type' -Default '') -match 'ManagedAppProtection$' }))
        $ios = @($prot | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Type' -Default '') -match 'ios' }); $and = @($prot | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Type' -Default '') -match 'android' })
        if ($ios.Count -gt 0 -and $and.Count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.4' -State 'Satisfied' -Category 'Endpoint' -Title $c.Title -Severity 'Informational' -FrameworkIds (& $cit 'INT-1.4') `
                -Detail "Assigned app protection policies cover iOS ($($ios.Count)) and Android ($($and.Count))." -CurrentValue "$($prot.Count) assigned app protection policies"
        } elseif ($prot.Count -gt 0) {
            $missing = if ($ios.Count -eq 0) { 'iOS' } else { 'Android' }
            Add-NRGFinding -ControlId 'INT-1.4' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.4') `
                -Detail "Assigned app protection policies exist, but none covers $missing." -RequiredValue 'App protection policies for iOS and Android' -Remediation $c.Remediation
        } else {
            Add-NRGFinding -ControlId 'INT-1.4' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.4') `
                -Detail 'No assigned app protection (MAM) policy. Corporate data in Office apps on personal devices is unprotected — users can copy/paste or save to personal storage.' `
                -CurrentValue 'No assigned app protection policies' -RequiredValue 'App protection policies for iOS and Android targeting Office apps' -Remediation $c.Remediation
        }
    }

    # INT-1.5 — Antivirus policy deployed via Intune (the Microsoft Defender
    # Antivirus template, assigned). The old fallback scored Partial from the
    # existence of enrollment configurations, which every tenant has.
    $c = Get-NRGControlById -ControlId 'INT-1.5'
    if ($c -and -not $collected['EndpointSecurityPolicies']) {
        Add-NRGFinding -ControlId 'INT-1.5' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.5') -Detail 'EndpointSecurityPolicies was not collected; not assessed.'
    } elseif ($c) {
        $av = @(Select-NRGAssignedPolicies @($d.EndpointSecurityPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'TemplateType') -eq 'Antivirus' }))
        if ($av.Count -gt 0) {
            # The expected state is that an assigned policy CONFIGURES Defender Antivirus:
            # real-time protection, cloud-delivered protection and PUA protection. The
            # policy existing is verified; the settings come from the collector's read.
            $read = @($av | Where-Object { (Get-NRGObjectField -Item $_ -Key 'AvSettingsStatus' -Default '') -eq 'Read' })
            $maps = @($read | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'AvSettings' -Default $null } | Where-Object { $null -ne $_ })
            $verified = @("$($av.Count) assigned Microsoft Defender Antivirus policy(ies).")
            $short = @(); $unknown = @()
            if ($read.Count -lt $av.Count) {
                $unknown += "the antivirus settings of $($av.Count - $read.Count) of $($av.Count) assigned policy(ies) could not be read, so real-time, cloud-delivered and PUA protection are not established."
            }
            if ($maps.Count -gt 0) {
                $label = @{ RealTimeProtection = 'Real-time protection'; CloudProtection = 'Cloud-delivered protection'; PuaProtection = 'PUA protection' }
                foreach ($row in @(Test-NRGAvSettingSet -SettingMaps $maps)) {
                    $l = $label[$row.Setting]
                    switch -Wildcard ($row.Value) {
                        'On'            { $verified += "$l is on."; break }
                        'Audit'         { $short += "$l is in audit mode only."; break }
                        'Off'           { $short += "$l is turned off."; break }
                        'NotConfigured' { if ($read.Count -eq $av.Count) { $unknown += "$l is not set by any assigned policy (the platform default may apply; the policy does not establish it)." }; break }
                        default         { $unknown += "$l has a value this tool does not recognize ($($row.Value))." }
                    }
                }
            }
            Add-NRGExpectedStateFinding -ControlId 'INT-1.5' -Control $c -FrameworkIds (& $cit 'INT-1.5') -Verified $verified -Shortfalls $short -NotEstablished $unknown `
                -CurrentValue "$($av.Count) AV policies assigned" -RequiredValue 'An assigned Defender Antivirus policy with real-time, cloud-delivered and PUA protection on'
        } else {
            Add-NRGFinding -ControlId 'INT-1.5' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.5') `
                -Detail 'No assigned Microsoft Defender Antivirus policy in Intune endpoint security. Devices have no managed antivirus configuration baseline.' -Remediation $c.Remediation
        }
    }
}

# Policies that are assigned to someone. IsAssigned $false is an unassigned
# draft; $null (not reported, e.g. replayed older results) is kept.
# Enrolled devices of a platform, from the managed-device inventory. $null
# when the inventory was not read (unknown is not zero). Microsoft's
# operatingSystem values: Windows, iOS, iPadOS, Android, AndroidEnterprise,
# AndroidForWork, macOS.
function Get-NRGEnrolledPlatformCount {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw, [Parameter(Mandatory)] [string] $Pattern)
    if (-not (Test-NRGSectionCollected $Raw 'OSComplianceSummary')) { return $null }
    $sum = Get-NRGObjectField -Item $Raw.Data -Key 'OSComplianceSummary' -Default $null
    $by  = Get-NRGObjectField -Item $sum -Key 'ByPlatform' -Default $null
    if ($null -eq $by) { return $null }
    $names = if ($by -is [System.Collections.IDictionary]) { @($by.Keys) } else { @($by.PSObject.Properties.Name) }
    $n = 0
    foreach ($k in $names) { if ([string]$k -match $Pattern) { $n += [int](Get-NRGObjectField -Item $by -Key $k -Default 0) } }
    return $n
}

# One line naming what IS enrolled, for a platform with none.
function Get-NRGEnrolledPlatformSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw)
    $sum = Get-NRGObjectField -Item $Raw.Data -Key 'OSComplianceSummary' -Default $null
    $by  = Get-NRGObjectField -Item $sum -Key 'ByPlatform' -Default $null
    if ($null -eq $by) { return 'no managed devices' }
    $names = if ($by -is [System.Collections.IDictionary]) { @($by.Keys) } else { @($by.PSObject.Properties.Name) }
    $parts = @($names | Sort-Object | ForEach-Object { "$([int](Get-NRGObjectField -Item $by -Key $_ -Default 0)) $_" })
    if ($parts.Count -eq 0) { return 'no managed devices' }
    return ($parts -join ', ')
}

function Select-NRGAssignedPolicies {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Policies)
    return @(@($Policies) | Where-Object { $null -ne $_ -and (Get-NRGObjectField -Item $_ -Key 'IsAssigned' -Default $null) -ne $false })
}

# Scored endpoint-security policies of one bucket, assigned only, with a
# phrase naming unassigned ones left out.
function Get-NRGIntuneBucketState {
    [CmdletBinding()]
    param([AllowNull()] $Raw, [Parameter(Mandatory)] [string] $Section)
    $all = @(Get-NRGObjectField -Item $Raw.Data -Key $Section -Default @() | Where-Object { $null -ne $_ })
    $assigned = @(Select-NRGAssignedPolicies $all)
    $note = if ($all.Count -gt $assigned.Count) { " $($all.Count - $assigned.Count) unassigned policy(ies) were not counted." } else { '' }
    return @{ Assigned = $assigned; Note = $note }
}

# ── INT-2.1 Endpoint Detection and Response Deployed ─────────────────────────
function Test-NRGControlIntuneEDR {
    [CmdletBinding()] param()
    $cid = 'INT-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $int 'EndpointDetectionPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EndpointDetectionPolicies was not collected; not assessed.'
        return
    }
    $st = Get-NRGIntuneBucketState -Raw $int -Section 'EndpointDetectionPolicies'
    if ($st.Assigned.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($st.Assigned.Count) assigned Microsoft Defender for Endpoint onboarding (EDR) policy(ies) deployed via Intune.$($st.Note)"
        return
    }

    # No Intune-managed Defender for Endpoint onboarding policy. A client on a
    # third-party EDR (Cortex XDR, CrowdStrike, SentinelOne, ...) is declared
    # per client with -ThirdPartyEDR / clients.json ThirdPartyEDR, or MSP-wide
    # with EdrStack in Config/branding.psd1; Set-NRGThirdPartyEdr then takes
    # this check out of the score as "declared, not verified". It used to be
    # scored Satisfied straight from the branding declaration — a pass on a
    # claim nothing verified — and Partial (half credit) for a manual review
    # when nothing was declared.
    Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail 'No Microsoft Defender for Endpoint onboarding policy is deployed via Intune. If this client runs a third-party EDR instead (Cortex XDR, CrowdStrike, SentinelOne, ...), declare it with -ThirdPartyEDR or ThirdPartyEDR in clients.json: the check is then reported as covered by that product (declared, not verified) and not scored.' `
        -CurrentValue 'No Intune-managed Defender for Endpoint onboarding policy' `
        -RequiredValue 'EDR onboarding deployed to every managed endpoint' `
        -Remediation $ctrl.Remediation
}

# ── INT-2.2 Attack Surface Reduction Rules Enabled ───────────────────────────
function Test-NRGControlIntuneASR {
    [CmdletBinding()] param()
    $cid = 'INT-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $int 'ASRPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ASRPolicies was not collected; not assessed.'
        return
    }
    $st = Get-NRGIntuneBucketState -Raw $int -Section 'ASRPolicies'
    if ($st.Assigned.Count -gt 0) {
        # The expected state is the approved NRG ASR rule set, every rule in Block
        # mode. The policy existing is verified; the rule modes come from the settings
        # read (collector), and the REQUIRED list is an operator-approved file (an empty
        # list means no standard is approved). Nothing is inferred: an unread mode is unknown, never Block.
        $asrPolicies = @($st.Assigned)
        $read   = @($asrPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'AsrSettingsStatus' -Default '') -eq 'Read' })
        $modeMaps = @($read | ForEach-Object { Get-NRGObjectField -Item $_ -Key 'AsrRuleModes' -Default $null } | Where-Object { $null -ne $_ })
        $allModes = @($modeMaps | ForEach-Object { @($_.Values) })
        $modeSummary = if ($allModes.Count -gt 0) { ($allModes | Group-Object | Sort-Object Name | ForEach-Object { "$($_.Count) in $($_.Name)" }) -join ', ' } else { '' }
        $required = @(Get-NRGAsrRequiredRules)
        $verified = "Verified: $($st.Assigned.Count) assigned Attack Surface Reduction Rules policy(ies).$($st.Note)"
        if ($read.Count -lt $asrPolicies.Count) {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "$verified Not assessed: the rule settings of $($asrPolicies.Count - $read.Count) of $($asrPolicies.Count) assigned policy(ies) could not be read, so which rules are configured and in what mode is not established.$(if ($modeSummary) { " Read so far: $modeSummary." })" `
                -CurrentValue "$($st.Assigned.Count) assigned ASR policy(ies); rule settings not fully read" `
                -RequiredValue 'The approved NRG ASR rule set with every rule in Block mode'
        } elseif ($required.Count -eq 0) {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "$verified Rule modes read: $(if ($modeSummary) { $modeSummary } else { 'no ASR rule settings found in the assigned policies' }). Not assessed: whether the approved NRG rule set is in Block mode, because no required rule list is approved (Config/asr-required-rules.json is empty)." `
                -CurrentValue "$($st.Assigned.Count) assigned ASR policy(ies); $(if ($modeSummary) { $modeSummary } else { 'no rule settings found' })" `
                -RequiredValue 'The approved NRG ASR rule set with every rule in Block mode'
        } else {
            $judge = Test-NRGAsrRuleSet -RuleModeMaps $modeMaps -Required $required
            if ($judge.NotBlock.Count -eq 0) {
                Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
                    -Detail "All $($judge.Required) required ASR rule(s) are in Block mode in the assigned policy(ies).$($st.Note)"
            } else {
                $list = ($judge.NotBlock | ForEach-Object { "$($_.Name) ($($_.Mode))" }) -join '; '
                $state = if ($judge.Blocking -gt 0) { 'Partial' } else { 'Gap' }
                Add-NRGFinding -ControlId $cid -State $state -Category $ctrl.Category -Title $ctrl.Title -Severity $(if ($state -eq 'Gap') { $ctrl.Severity } else { 'Medium' }) -FrameworkIds $cit `
                    -Detail "$verified Shortfall: $($judge.Required - $judge.Blocking) of $($judge.Required) required ASR rule(s) are not in Block mode: $list." `
                    -CurrentValue "$($judge.Blocking) of $($judge.Required) required rules in Block mode" `
                    -RequiredValue 'Every approved NRG ASR rule in Block mode' -Remediation $ctrl.Remediation `
                    -AffectedObjects @($judge.NotBlock | ForEach-Object { [ordered]@{ Rule = $_.Name; Mode = $_.Mode } })
            }
        }
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Attack Surface Reduction Rules policy in Intune (Device Control, Exploit Protection and other templates in the same family are not ASR rules).$($st.Note) ASR rules block commodity malware delivery such as Office macro abuse and credential theft." -Remediation $ctrl.Remediation
    }
}

# ── INT-2.3 Firewall Policy Deployed via Intune ───────────────────────────────
function Test-NRGControlIntuneFirewall {
    [CmdletBinding()] param()
    $cid = 'INT-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $int 'FirewallPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'FirewallPolicies was not collected; not assessed.'
        return
    }
    $st = Get-NRGIntuneBucketState -Raw $int -Section 'FirewallPolicies'
    if ($st.Assigned.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($st.Assigned.Count) assigned Windows Firewall policy(ies) deployed via Intune.$($st.Note)"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Windows Firewall policy in Intune (a firewall RULES policy alone does not turn the firewall on).$($st.Note) Endpoint firewall configuration is unmanaged." -Remediation $ctrl.Remediation
    }
}

# ── INT-2.4 Disk Encryption Compliance for macOS ─────────────────────────────
function Test-NRGControlIntuneMacEncryption {
    [CmdletBinding()] param()
    $cid = 'INT-2.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune compliance data not collected'; return }
    if (-not (Test-NRGSectionCollected $int 'CompliancePolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'CompliancePolicies was not collected; not assessed.'; return
    }
    $macDevices  = Get-NRGEnrolledPlatformCount -Raw $int -Pattern '^macOS'
    $macPolicies = @(Select-NRGAssignedPolicies @(@(Get-NRGObjectField -Item $int.Data -Key 'CompliancePolicies' -Default @()) | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Platform') -match 'macOS|Mac' }))
    if ($macDevices -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No macOS devices are enrolled in Intune (enrolled: $(Get-NRGEnrolledPlatformSummary -Raw $int)), so no Mac is governed by a compliance policy either way."
        return
    }
    if ($macPolicies.Count -eq 0) {
        if ($macDevices -gt 0) {
            Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "$macDevices macOS device(s) are enrolled, but no assigned macOS compliance policy requires FileVault. A lost or stolen Mac exposes whatever it holds." `
                -CurrentValue "$macDevices Mac(s), no macOS compliance policy" -RequiredValue 'Assigned macOS compliance policy requiring FileVault (Require encryption of data storage)' -Remediation $ctrl.Remediation
        } else {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail 'No assigned macOS compliance policy, and the managed-device inventory was not read, so whether any Mac is enrolled is unknown. Not assessed.'
        }
        return
    }
    # FileVault is storageRequireEncryption. System Integrity Protection, which
    # used to be accepted as well, is unrelated to disk encryption.
    $encRequired = @($macPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'StorageRequireEncryption') -eq $true }).Count -gt 0
    if ($encRequired) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'macOS compliance policy requires FileVault encryption.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'macOS compliance policy does not require FileVault encryption. Stolen Macs expose all organizational data.' -Remediation $ctrl.Remediation
    }
}

# ── INT-2.5 Windows Update Compliance Policy ─────────────────────────────────
function Test-NRGControlIntuneWindowsUpdate {
    [CmdletBinding()] param()
    $cid = 'INT-2.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune compliance data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $int 'UpdatePolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'UpdatePolicies was not collected; not assessed.'
        return
    }
    $winUpdatePolicies = @(Select-NRGAssignedPolicies @(Get-NRGObjectField -Item $int.Data -Key 'UpdatePolicies' -Default @()))
    if ($winUpdatePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($winUpdatePolicies.Count) assigned Windows Update for Business ring(s)."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Windows Update for Business policy found in Intune. Endpoints may not receive security updates on a managed schedule. Verify via Windows Update rings.' -Remediation $ctrl.Remediation
    }
}

# ── INT-3.1 Device Enrollment Restrictions Configured ────────────────────────
function Test-NRGControlIntuneEnrollmentRestrictions {
    [CmdletBinding()] param()
    $cid = 'INT-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-NRGSectionCollected $int 'EnrollmentRestrictions')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Enrollment restrictions were not collected; not assessed.'; return
    }
    # Every tenant has the default restrictions ("All users and all devices",
    # priority 0), which allow every platform and personal devices. Their
    # presence is not a restriction; a block inside one — default or custom —
    # is. Results collected before the per-platform blocks were read carry no
    # Restrictions field and are not assessed.
    $rows = @(Get-NRGObjectField -Item $int.Data -Key 'EnrollmentRestrictions' -Default @() | Where-Object { $null -ne $_ })
    $platformRows = @($rows | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Type' -Default '') -match 'PlatformRestriction' })
    if (@($platformRows | Where-Object { $null -eq (Get-NRGObjectField -Item $_ -Key 'Restrictions' -Default $null) }).Count -gt 0 -or $platformRows.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The platform restriction settings were not collected; not assessed.'; return
    }
    # Windows Mobile is retired and Intune blocks it in the default
    # configuration of every tenant, so that block restricts nothing anyone
    # enrolls. A live tenant passed on "windowsMobile: platform blocked" alone.
    $blocks = @($platformRows | ForEach-Object { @(Get-NRGObjectField -Item $_ -Key 'Restrictions' -Default @()) } | Where-Object {
        $_ -and [string]$_.Platform -ne 'windowsMobile' -and ($_.PlatformBlocked -or $_.PersonalBlocked -or $_.OsMinimumVersion) })
    if ($blocks.Count -gt 0) {
        $what = @($blocks | ForEach-Object { "$($_.Platform): $(@(if ($_.PlatformBlocked) { 'platform blocked' }; if ($_.PersonalBlocked) { 'personal devices blocked' }; if ($_.OsMinimumVersion) { "min OS $($_.OsMinimumVersion)" }) -join ', ')" })
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Enrollment is restricted: $($what -join '; ')."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Enrollment restrictions are at their defaults: every platform may enroll, personal devices included, with no minimum OS version. Any user can enroll any device and have it treated as managed.' `
            -CurrentValue 'Default restrictions only (nothing blocked)' -RequiredValue 'Block personal enrollment and unused platforms, set minimum OS versions' -Remediation $ctrl.Remediation
    }
}

# ── INT-3.2 Mobile App Configuration Policies Deployed ───────────────────────
function Test-NRGControlIntuneAppConfig {
    [CmdletBinding()] param()
    $cid = 'INT-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-AppProtection'
    if (-not $int -or -not $int.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Intune app protection data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $int 'AppConfigPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AppConfigPolicies was not collected; not assessed.'
        return
    }
    $appConfig = @($int.Data['AppConfigPolicies'] ?? @())
    if ($appConfig.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($appConfig.Count) app configuration policy(ies) deployed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No app configuration policies found. Managed apps may use default settings without security baseline configuration.' `
            -Remediation $ctrl.Remediation
    }
}

# ── INT-3.3 Conditional Launch Policies Configured ───────────────────────────
function Test-NRGControlIntuneConditionalLaunch {
    [CmdletBinding()] param()
    $cid = 'INT-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-AppProtection'
    if (-not $int -or -not $int.Success -or -not (Test-NRGSectionCollected $int 'AppProtectionPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'App protection policies were not collected; not assessed.'; return
    }
    # Jailbreak / root blocking and the PIN-retry and offline-wipe limits
    # are on by DEFAULT in every app protection policy, so their presence
    # proved nothing (every policy passed). The setting an admin must choose
    # is a minimum OS version for the apps to open.
    $prot = @(Select-NRGAssignedPolicies @(@(Get-NRGObjectField -Item $int.Data -Key 'AppProtectionPolicies' -Default @()) | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Type' -Default '') -match 'ManagedAppProtection$' }))
    if ($prot.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No assigned app protection policy exists, so no conditional launch check applies to corporate apps on mobile devices.' -Remediation $ctrl.Remediation
        return
    }
    $withOs = @($prot | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'MinimumRequiredOsVersion' -Default '') })
    if ($withOs.Count -eq $prot.Count) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Every assigned app protection policy ($($prot.Count)) blocks apps on devices below a minimum OS version, in addition to the default jailbreak / root block."
    } elseif ($withOs.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($withOs.Count) of $($prot.Count) assigned app protection policies set a minimum OS version; apps under the others open on any OS version." -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No assigned app protection policy sets a minimum OS version, so corporate apps open on out-of-support, unpatched mobile OS versions (only the default jailbreak / root block applies).' `
            -CurrentValue "$($prot.Count) policy(ies), none with a minimum OS version" -RequiredValue 'Conditional launch: minimum OS version (block access)' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.1 Windows LAPS Configured ──────────────────────────────────────────
function Test-NRGControlIntuneWindowsLAPS {
    [CmdletBinding()] param()
    $cid = 'INT-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $int 'LAPSPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'LAPSPolicies was not collected; not assessed.'
        return
    }
    $st = Get-NRGIntuneBucketState -Raw $int -Section 'LAPSPolicies'
    if ($st.Assigned.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($st.Assigned.Count) assigned Windows LAPS policy(ies).$($st.Note) (The backup directory and rotation settings inside the policy are not read.)"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Windows LAPS policy (Account Protection policies such as Credential Guard are not LAPS).$($st.Note) If endpoints share a local admin password, one compromise opens every endpoint." -Remediation $ctrl.Remediation
    }
}

# ── INT-4.2 Windows Hello for Business Deployed ───────────────────────────────
function Test-NRGControlIntuneWindowsHello {
    [CmdletBinding()] param()
    $cid = 'INT-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-NRGSectionCollected $int 'WindowsHelloPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Windows Hello for Business enrollment configuration was not collected; not assessed.'; return
    }
    # Every tenant has the default WHfB enrollment configuration; its State
    # (enabled / disabled / notConfigured) is the setting. Its mere presence
    # passed every tenant.
    $rows = @(Get-NRGObjectField -Item $int.Data -Key 'WindowsHelloPolicies' -Default @() | Where-Object { $null -ne $_ })
    $states = @($rows | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') })
    if (@($states | Where-Object { $_ -eq 'enabled' }).Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Windows Hello for Business is enabled in the Intune enrollment configuration — devices are provisioned with phishing-resistant sign-in.'
    } elseif (@($states | Where-Object { $_ }).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The Windows Hello for Business enrollment state was not returned; not assessed.'
    } else {
        $how = if ($states -contains 'disabled') { 'disabled' } else { 'not configured (Intune does not manage it; Windows'' own default applies)' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Windows Hello for Business is $how in the Intune enrollment configuration. (A setting made in an Account Protection or settings-catalog policy instead is not read here.)" `
            -CurrentValue "State = $($states -join ', ')" -RequiredValue 'Windows Hello for Business enabled' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.3 Update Compliance / Windows Update for Business Reports ───────────
function Test-NRGControlIntuneUpdateCompliance {
    [CmdletBinding()] param()
    $cid = 'INT-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-NRGSectionCollected $int 'CompliancePolicies') -or -not (Test-NRGSectionCollected $int 'OSComplianceSummary')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Compliance policies or the managed-device summary were not collected; not assessed.'; return
    }
    # Two halves. A minimum OS version must be a compliance rule; without one
    # a device's "compliant" state says nothing about its OS version, which
    # is what was reported as "OS-version compliant" before.
    $policies = @(Select-NRGAssignedPolicies @(Get-NRGObjectField -Item $int.Data -Key 'CompliancePolicies' -Default @()))
    $hasKey = { param($p) if ($p -is [System.Collections.IDictionary]) { $p.Contains('OsMinimumVersion') } else { [bool]$p.PSObject.Properties['OsMinimumVersion'] } }
    if ($policies.Count -gt 0 -and @($policies | Where-Object { & $hasKey $_ }).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Minimum OS versions in compliance policies were not collected; not assessed.'; return
    }
    $withMin = @($policies | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'OsMinimumVersion' -Default '') })
    if ($withMin.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No assigned compliance policy sets a minimum OS version, so a device on an out-of-support OS is still compliant.' `
            -RequiredValue 'Minimum OS version in compliance policies, and at least 90% of devices compliant' -Remediation $ctrl.Remediation
        return
    }
    $total = [int](Get-NRGNestedProperty -Object $int -Path 'Data.OSComplianceSummary.TotalCount' -Default 0)
    $ok    = [int](Get-NRGNestedProperty -Object $int -Path 'Data.OSComplianceSummary.CompliantCount' -Default 0)
    if ($total -le 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "$($withMin.Count) compliance policy(ies) set a minimum OS version, but no managed devices were returned to measure compliance against."
        return
    }
    $pct = [int][math]::Floor($ok * 100 / $total)
    if ($pct -ge 90) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($withMin.Count) compliance policy(ies) set a minimum OS version, and $pct% of managed devices ($ok/$total) are compliant with their policies."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Only $pct% of managed devices ($ok/$total) are compliant with their compliance policies (minimum OS version among the rules); $($total - $ok) are not." -CurrentValue "$pct% compliant" -RequiredValue 'At least 90% compliant' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.4 Mobile Device Compliance Policy Requires PIN/Biometric ────────────
function Test-NRGControlIntuneMobilePIN {
    [CmdletBinding()] param()
    $cid = 'INT-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-NRGSectionCollected $int 'CompliancePolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'CompliancePolicies was not collected; not assessed.'; return
    }
    $mobileDevices = Get-NRGEnrolledPlatformCount -Raw $int -Pattern '^(iOS|iPadOS|Android)'
    if ($mobileDevices -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No iOS, iPadOS or Android devices are enrolled in Intune (enrolled: $(Get-NRGEnrolledPlatformSummary -Raw $int)), so a mobile compliance setting governs no device. Phones reaching company data without enrolling are covered by app protection (INT-1.4)."
        return
    }
    $mobile = @(Select-NRGAssignedPolicies @(@(Get-NRGObjectField -Item $int.Data -Key 'CompliancePolicies' -Default @()) | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Platform') -match 'ios|android' }))
    if ($mobile.Count -eq 0) {
        if ($mobileDevices -gt 0) {
            Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "$mobileDevices mobile device(s) are enrolled, but no assigned iOS or Android compliance policy requires a passcode." -Remediation $ctrl.Remediation
        } else {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail 'No assigned iOS or Android compliance policy, and the managed-device inventory was not read, so whether any mobile device is enrolled is unknown. Not assessed.'
        }
        return
    }
    # iOS names it passcodeRequired; Android passwordRequired. Reading only
    # passwordRequired failed every iOS-only fleet.
    $req = { param($p) (Get-NRGObjectField -Item $p -Key 'PasscodeRequired' -Default $null) -eq $true -or (Get-NRGObjectField -Item $p -Key 'PasswordRequired' -Default $null) -eq $true }
    $platforms = @($mobile | ForEach-Object { if ((Get-NRGObjectField -Item $_ -Key 'Platform') -match 'ios') { 'iOS' } else { 'Android' } } | Sort-Object -Unique)
    $covered = @($platforms | Where-Object { $pl = $_; @($mobile | Where-Object { ((Get-NRGObjectField -Item $_ -Key 'Platform') -match ($(if ($pl -eq 'iOS') { 'ios' } else { 'android' }))) -and (& $req $_) }).Count -gt 0 })
    if ($covered.Count -eq $platforms.Count) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Mobile compliance policies require a device passcode on $($platforms -join ' and ')."
    } elseif ($covered.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "A passcode is required on $($covered -join ', ') but not on $(@($platforms | Where-Object { $_ -notin $covered }) -join ', ')." -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Mobile compliance policies do not require a device passcode. A lost or stolen unlocked device exposes corporate data.' -Remediation $ctrl.Remediation
    }
}

#Requires -Version 7.0
#
# Test-TPControlIntune.ps1
# Evaluates Intune controls. Reads from the three split raw-data keys produced by
# Invoke-TPCollectIntuneEndpointSecurity / DeviceCompliance / AppProtection.
#
# Controls: INT-1.1 through INT-4.4 (17 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#

function Test-TPControlIntune {
    [CmdletBinding()] param()
    $es  = Get-TPRawData -Key 'Intune-EndpointSecurity'
    $dc  = Get-TPRawData -Key 'Intune-DeviceCompliance'
    $app = Get-TPRawData -Key 'Intune-AppProtection'

    $anySuccess = ($es -and $es.Success) -or ($dc -and $dc.Success) -or ($app -and $app.Success)
    if (-not $anySuccess) {
        foreach ($cid in @('INT-1.1','INT-1.2','INT-1.3','INT-1.4','INT-1.5')) {
            $c = Get-TPControlById -ControlId $cid
            if ($c) {
                Add-TPFinding -ControlId $cid -State 'NotApplicable' `
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
        CompliancePolicies       = (Test-TPSectionCollected $dc  'CompliancePolicies')
        ConfigurationProfiles    = (Test-TPSectionCollected $dc  'ConfigurationProfiles')
        AppProtectionPolicies    = (Test-TPSectionCollected $app 'AppProtectionPolicies')
        EnrollmentConfig         = (Test-TPSectionCollected $dc  'EnrollmentConfig')
        EndpointSecurityPolicies = (Test-TPSectionCollected $es  'EndpointSecurityPolicies')
    }
    $d = @{
        CompliancePolicies       = & $pick $dc  'CompliancePolicies'
        ConfigurationProfiles    = & $pick $dc  'ConfigurationProfiles'
        AppProtectionPolicies    = & $pick $app 'AppProtectionPolicies'
        EnrollmentConfig         = & $pick $dc  'EnrollmentConfig'
        EndpointSecurityPolicies = & $pick $es  'EndpointSecurityPolicies'
    }

    $cit = { param($id) Get-TPFrameworkCitations -ControlId $id }

    # ITN-1.1 — Device compliance policies, counting only ASSIGNED ones: an
    # unassigned policy evaluates no device.
    $c = Get-TPControlById -ControlId 'INT-1.1'
    if ($c -and -not $collected['CompliancePolicies']) {
        Add-TPFinding -ControlId 'INT-1.1' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') -Detail 'CompliancePolicies was not collected; not assessed.'
    } elseif ($c) {
        $all = @($d.CompliancePolicies)
        $assigned = @(Select-TPAssignedPolicies $all)
        if ($assigned.Count -gt 0) {
            # The expected state is an assigned compliance policy PER enrolled platform,
            # each with a non-compliance action. One assigned policy covers one platform,
            # not the fleet, so coverage is judged per platform from the enrolled-device
            # counts. The actions come from the collector's scheduledActionsForRule read
            # (Get-TPComplianceActionVerdict): a policy whose actions were not read leaves
            # the control not assessed, never credited and never faulted.
            $plats = @(
                @{ Name = 'Windows'; Device = '^Windows';     Policy = '(?i)windows' }
                @{ Name = 'iOS/iPadOS'; Device = '^(iOS|iPadOS)'; Policy = '(?i)\bios|ipados' }
                @{ Name = 'Android'; Device = '^Android';     Policy = '(?i)android' }
                @{ Name = 'macOS'; Device = '^macOS';         Policy = '(?i)macos' }
            )
            $unread = $null -eq (Get-TPEnrolledPlatformCount -Raw $dc -Pattern '.')
            $covered = @(); $uncovered = @()
            if (-not $unread) {
                foreach ($pl in $plats) {
                    $n = [int](Get-TPEnrolledPlatformCount -Raw $dc -Pattern $pl.Device)
                    if ($n -le 0) { continue }
                    $has = @($assigned | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Platform' -Default '') -match $pl.Policy }).Count -gt 0
                    if ($has) { $covered += "$($pl.Name) ($n device(s))" } else { $uncovered += "$($pl.Name) ($n device(s))" }
                }
            }
            $verified = "Verified: $($assigned.Count) assigned compliance policy(ies)."
            $av  = Get-TPComplianceActionVerdict -Policies $assigned
            $req = 'An assigned compliance policy per enrolled platform, each with a non-compliance action'
            $actionsNote = if ($av.Unread.Count -gt 0) { "the non-compliance actions of $($av.Unread.Count) policy(ies) were not read ($($av.Unread -join ', '))" } else { '' }
            if ($unread) {
                Add-TPFinding -ControlId 'INT-1.1' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified Not assessed: whether every enrolled platform has one, because the enrolled-device platform counts were not read$(if ($actionsNote) { "; and $actionsNote" })." `
                    -CurrentValue "$($assigned.Count) assigned compliance policy(ies); platform coverage not read" -RequiredValue $req
            } elseif ($uncovered.Count -gt 0) {
                Add-TPFinding -ControlId 'INT-1.1' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified$(if ($covered.Count) { " Covered: $($covered -join ', ')." }) Shortfall: no assigned compliance policy for $($uncovered -join ', '), so those devices are not held to any baseline." `
                    -CurrentValue "Covered: $($covered -join ', '); not covered: $($uncovered -join ', ')" -RequiredValue 'An assigned compliance policy per enrolled platform, each with a non-compliance action' -Remediation $c.Remediation
            } elseif ($av.Unread.Count -gt 0) {
                Add-TPFinding -ControlId 'INT-1.1' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified Every enrolled platform has an assigned compliance policy ($($covered -join ', ')). Not assessed: $actionsNote, so the action half of the requirement is not established." `
                    -CurrentValue "Platforms covered: $($covered -join ', '); non-compliance action not read" -RequiredValue $req
            } elseif ($av.Lacking.Count -gt 0) {
                Add-TPFinding -ControlId 'INT-1.1' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified Every enrolled platform has an assigned compliance policy ($($covered -join ', ')).$(if ($av.Acting.Count) { " Verified: $($av.Acting.Count) policy(ies) act on a noncompliant device: $($av.Acting -join '; ')." }) Shortfall: $($av.Lacking.Count) assigned policy(ies) take no action on a noncompliant device beyond a notification ($($av.Lacking -join ', ')), so a device failing one of them is not held to anything." `
                    -CurrentValue "Platforms covered: $($covered -join ', '); no action beyond a notification: $($av.Lacking -join ', ')" -RequiredValue $req -Remediation $c.Remediation
            } else {
                Add-TPFinding -ControlId 'INT-1.1' -State 'Satisfied' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.1') `
                    -Detail "$verified Every enrolled platform has an assigned compliance policy ($($covered -join ', ')). Every assigned policy acts on a noncompliant device: $($av.Acting -join '; '). (The configured actions are read from the policy; whether Intune applied them to a device is not.)" `
                    -CurrentValue "Platforms covered: $($covered -join ', '); actions: $($av.Acting -join '; ')" -RequiredValue $req
            }
        } else {
            $why = if ($all.Count) { "$($all.Count) compliance policy(ies) exist but none is assigned to any user or device." } else { 'No device compliance policies configured.' }
            Add-TPFinding -ControlId 'INT-1.1' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.1') `
                -Detail "$why Devices no policy evaluates are not held to any baseline." `
                -CurrentValue 'No assigned compliance policies' -RequiredValue 'At least one assigned compliance policy' -Remediation $c.Remediation
        }
    }

    # INT-1.2 — Non-compliant device access blocked via Conditional Access.
    # It read "any configuration profile exists" (a Wi-Fi profile passed). The
    # control is a CA policy requiring a compliant (or hybrid-joined) device.
    $c = Get-TPControlById -ControlId 'INT-1.2'
    # While Security Defaults is enabled no CA policy can be turned on, and it
    # has no device-compliance requirement of its own: a Gap, and a report-only
    # compliant-device policy beside it earns nothing (same as AAD-2.3).
    if ($c -and (Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId 'INT-1.2' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.2') -State 'Gap' -Severity $c.Severity `
            -Detail 'No policy in force requires a compliant device: Security Defaults has no device-compliance requirement, so a device Intune marks non-compliant (or one never enrolled) still reaches Microsoft 365.' `
            -CurrentValue 'Security Defaults enabled; no compliant-device requirement in force' `
            -RequiredValue 'Enabled CA policy requiring a compliant device for all users on all cloud apps' `
            -Remediation $c.Remediation -NeedsConditionalAccess
    } elseif ($c) {
        $ca = Get-TPRawData -Key 'AAD-CAPolicies'
        if (-not $ca -or -not $ca.Success) {
            Add-TPFinding -ControlId 'INT-1.2' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.2') -Detail 'Conditional Access policies were not collected; not assessed.'
        } else {
            # One judgment shared with AAD-2.3 (Get-TPCADeviceComplianceCoverage): the
            # requirement counts only from enabled policies that require a device of
            # all users on all applications with no narrowing, reaching the browser
            # and the desktop and mobile clients, exclusions combined across policies.
            # The private check this replaced read "All users" and "All applications"
            # only, so a policy excluding users or applications, limited to the
            # browser, a platform, a location or a device filter still passed and the
            # finding claimed protection for everyone (2026-10-15 review).
            $pols = @(Get-TPObjectField -Item $ca.Data -Key 'Policies' -Default @() | Where-Object { $null -ne $_ })
            Add-TPCADeviceComplianceFinding -ControlId 'INT-1.2' -Control $c -FrameworkIds (& $cit 'INT-1.2') `
                -Model (Get-TPCADeviceComplianceCoverage -Policies $pols) `
                -Consequence 'A device Intune marks non-compliant (or one never enrolled) still reaches Microsoft 365.' `
                -RequiredValue 'Enabled CA policy requiring a compliant device for all users on all cloud apps'
        }
    }

    # INT-1.3 — Windows compliance policy requires BitLocker: "Require BitLocker"
    # (bitLockerEnabled, a Device Health Attestation rule) in every assigned Windows
    # compliance policy. "Require encryption of data storage on device"
    # (storageRequireEncryption) is a different rule: Microsoft's Zero Trust
    # recommended Windows compliance settings list both, and it crediting the
    # control alone passed a policy that never asks for BitLocker. It is shown as
    # context only. A policy whose bitLockerEnabled was not returned (a Windows
    # 8.1 or Phone policy type has no such rule) is not established, never credited.
    $c = Get-TPControlById -ControlId 'INT-1.3'
    if ($c -and -not $collected['CompliancePolicies']) {
        Add-TPFinding -ControlId 'INT-1.3' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.3') -Detail 'CompliancePolicies was not collected; not assessed.'
    } elseif ($c) {
        $winPolicies = @(Select-TPAssignedPolicies @($d.CompliancePolicies | Where-Object { (Get-TPObjectField -Item $_ -Key 'Platform') -match 'windows10|Windows' }))
        $polName = { param($p) $n = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default ''); if ($n) { $n } else { [string](Get-TPObjectField -Item $p -Key 'Id' -Default 'unnamed policy') } }
        $bitLocker = @(); $lacking = @(); $unread = @(); $storageOnly = @()
        foreach ($p in $winPolicies) {
            $bl = Get-TPObjectField -Item $p -Key 'BitLockerEnabled' -Default $null
            if ($bl -eq $true) { $bitLocker += (& $polName $p) }
            elseif ($bl -eq $false) {
                $lacking += (& $polName $p)
                if ((Get-TPObjectField -Item $p -Key 'StorageRequireEncryption' -Default $null) -eq $true) { $storageOnly += (& $polName $p) }
            } else { $unread += (& $polName $p) }
        }
        $req = 'Require BitLocker = Require (bitLockerEnabled) in every assigned Windows compliance policy'
        $storageNote = if ($storageOnly.Count) { " $($storageOnly.Count) of them require encryption of data storage on the device ($($storageOnly -join ', ')), a different rule that is not counted here." } else { '' }
        if ($winPolicies.Count -eq 0) {
            Add-TPFinding -ControlId 'INT-1.3' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.3') `
                -Detail 'No assigned Windows compliance policy exists, so no Windows device is required to have BitLocker.' -RequiredValue $req -Remediation $c.Remediation
        } elseif ($lacking.Count -gt 0 -and $bitLocker.Count -gt 0) {
            Add-TPFinding -ControlId 'INT-1.3' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.3') `
                -Detail "Verified: $($bitLocker.Count) assigned Windows compliance policy(ies) require BitLocker ($($bitLocker -join ', ')). Shortfall: $($lacking.Count) do not ($($lacking -join ', ')), so devices under them are not required to have BitLocker.$storageNote$(if ($unread.Count) { " Not assessed: whether $($unread -join ', ') require BitLocker (the setting was not returned)." })" `
                -CurrentValue "Require BitLocker: $($bitLocker.Count) of $($winPolicies.Count) assigned Windows policies" -RequiredValue $req -Remediation $c.Remediation
        } elseif ($lacking.Count -gt 0) {
            Add-TPFinding -ControlId 'INT-1.3' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.3') `
                -Detail "Shortfall: no assigned Windows compliance policy requires BitLocker ($($lacking.Count) checked: $($lacking -join ', ')). Unencrypted devices can access corporate data.$storageNote$(if ($unread.Count) { " Not assessed: whether $($unread -join ', ') require BitLocker (the setting was not returned)." })" `
                -CurrentValue "Require BitLocker not set in $($lacking.Count) Windows policy(ies)" -RequiredValue $req -Remediation $c.Remediation
        } elseif ($unread.Count -gt 0) {
            Add-TPFinding -ControlId 'INT-1.3' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.3') `
                -Detail "$(if ($bitLocker.Count) { "Verified: $($bitLocker.Count) assigned Windows compliance policy(ies) require BitLocker ($($bitLocker -join ', ')). " })Not assessed: whether $($unread -join ', ') require BitLocker, because the Require BitLocker setting was not returned for them (a Windows 8.1 or Windows Phone policy type has no such rule)." `
                -CurrentValue "Require BitLocker not read for $($unread.Count) policy(ies)" -RequiredValue $req
        } else {
            Add-TPFinding -ControlId 'INT-1.3' -State 'Satisfied' -Category 'Endpoint' -Title $c.Title -Severity 'Informational' -FrameworkIds (& $cit 'INT-1.3') `
                -Detail "Every assigned Windows compliance policy ($($winPolicies.Count): $($bitLocker -join ', ')) requires BitLocker (Device Health Attestation). The rule is read from the policy; whether each device reports BitLocker on is not." `
                -CurrentValue "Require BitLocker in $($winPolicies.Count) of $($winPolicies.Count) assigned Windows policies"
        }
    }

    # INT-1.4 — App protection (MAM) policies for iOS and Android. App
    # CONFIGURATION policies (also returned by managedAppPolicies) protect
    # nothing and are no longer counted.
    $c = Get-TPControlById -ControlId 'INT-1.4'
    if ($c -and -not $collected['AppProtectionPolicies']) {
        Add-TPFinding -ControlId 'INT-1.4' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.4') -Detail 'AppProtectionPolicies was not collected; not assessed.'
    } elseif ($c) {
        $prot = @(Select-TPAssignedPolicies @($d.AppProtectionPolicies | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Type' -Default '') -match 'ManagedAppProtection$' }))
        $ios = @($prot | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Type' -Default '') -match 'ios' }); $and = @($prot | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Type' -Default '') -match 'android' })
        if ($ios.Count -gt 0 -and $and.Count -gt 0) {
            Add-TPFinding -ControlId 'INT-1.4' -State 'Satisfied' -Category 'Endpoint' -Title $c.Title -Severity 'Informational' -FrameworkIds (& $cit 'INT-1.4') `
                -Detail "Assigned app protection policies cover iOS ($($ios.Count)) and Android ($($and.Count))." -CurrentValue "$($prot.Count) assigned app protection policies"
        } elseif ($prot.Count -gt 0) {
            $missing = if ($ios.Count -eq 0) { 'iOS' } else { 'Android' }
            Add-TPFinding -ControlId 'INT-1.4' -State 'Partial' -Category 'Endpoint' -Title $c.Title -Severity 'Medium' -FrameworkIds (& $cit 'INT-1.4') `
                -Detail "Assigned app protection policies exist, but none covers $missing." -RequiredValue 'App protection policies for iOS and Android' -Remediation $c.Remediation
        } else {
            Add-TPFinding -ControlId 'INT-1.4' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.4') `
                -Detail 'No assigned app protection (MAM) policy. Corporate data in Office apps on personal devices is unprotected — users can copy/paste or save to personal storage.' `
                -CurrentValue 'No assigned app protection policies' -RequiredValue 'App protection policies for iOS and Android targeting Office apps' -Remediation $c.Remediation
        }
    }

    # INT-1.5 — Antivirus policy deployed via Intune (the Microsoft Defender
    # Antivirus template, assigned). The old fallback scored Partial from the
    # existence of enrollment configurations, which every tenant has.
    $c = Get-TPControlById -ControlId 'INT-1.5'
    if ($c -and -not $collected['EndpointSecurityPolicies']) {
        Add-TPFinding -ControlId 'INT-1.5' -State 'NotApplicable' -Category 'Endpoint' -Title $c.Title -FrameworkIds (& $cit 'INT-1.5') -Detail 'EndpointSecurityPolicies was not collected; not assessed.'
    } elseif ($c) {
        $av = @(Select-TPAssignedPolicies @($d.EndpointSecurityPolicies | Where-Object { (Get-TPObjectField -Item $_ -Key 'TemplateType') -eq 'Antivirus' }))
        $baseline = Get-TPIntuneAvBaseline
        $avRead = @($av | Where-Object { (Get-TPObjectField -Item $_ -Key 'AvSettingsStatus' -Default '') -eq 'Read' })
        # The approved standard is judged only from policies the collector stored every
        # value of; a results file from before that read keeps the three-setting judgment.
        $valueMaps = @($avRead | ForEach-Object { Get-TPObjectField -Item $_ -Key 'AvSettingValues' -Default $null } | Where-Object { $null -ne $_ })
        if ($av.Count -gt 0 -and $null -ne $baseline -and $avRead.Count -gt 0 -and $valueMaps.Count -eq $avRead.Count) {
            # The expected state is the approved configuration standard: every setting of
            # the CIS Intune for Defender Antivirus benchmark (Level 1 - Workstation) in the
            # Antivirus profile set by policy to a value the benchmark accepts. Not set is a
            # shortfall (the not-configured rule): the benchmark requires the setting managed,
            # and the Windows default is named in the finding, never credited.
            $rows = @(Get-TPAvBaselineRows -SettingMaps $valueMaps -Catalog $baseline)
            $met = @($rows | Where-Object Status -eq 'Met')
            $below = @($rows | Where-Object Status -eq 'Below')
            $unset = @($rows | Where-Object Status -eq 'NotSet')
            $odd = @($rows | Where-Object Status -eq 'Unrecognized')
            $verified = @("$($av.Count) assigned Microsoft Defender Antivirus policy(ies).")
            if ($met.Count) { $verified += "$($met.Count) of $($rows.Count) settings of the $($baseline.Name) ($($baseline.Profile)) meet it: $(($met.Cis) -join ', ')." }
            $short = @(); $unknown = @()
            if ($below.Count) {
                $short += 'Set to a value the benchmark does not accept: ' + (($below | ForEach-Object { "$($_.Cis) $($_.Title) ($(@($_.Observed) -join ' / '); requires $($_.Required))" }) -join '; ') + '.'
            }
            if ($unset.Count) {
                $short += 'Not set by any assigned policy, which the benchmark requires: ' + (($unset | ForEach-Object {
                    if ($null -ne $_.WindowsDefault) { "$($_.Cis) $($_.Title) (Windows default $($_.WindowsDefault))" } else { "$($_.Cis) $($_.Title)" } }) -join '; ') + '.'
            }
            if ($odd.Count) {
                $unknown += 'a value Microsoft does not document for ' + (($odd | ForEach-Object { "$($_.Cis) $($_.Title) ($(@($_.Observed) -join ' / '))" }) -join '; ') + '.'
            }
            if ($avRead.Count -lt $av.Count) {
                $unknown += "the settings of $($av.Count - $avRead.Count) of $($av.Count) assigned policy(ies) could not be read, so no setting is established for the devices they target."
            }
            $affected = @($rows | Where-Object Status -ne 'Met' | ForEach-Object {
                [ordered]@{ Cis = $_.Cis; Setting = $_.Title; Status = $_.Status; Observed = (@($_.Observed) -join ' / '); Required = $_.Required; WindowsDefault = $_.WindowsDefault } })
            Add-TPExpectedStateFinding -ControlId 'INT-1.5' -Control $c -FrameworkIds (& $cit 'INT-1.5') -Verified $verified -Shortfalls $short -NotEstablished $unknown `
                -AffectedObjects $affected `
                -CurrentValue "$($met.Count) of $($rows.Count) benchmark settings met across $($av.Count) assigned AV policy(ies)" `
                -RequiredValue "$($baseline.Name), $($baseline.Profile): all $($rows.Count) Antivirus-profile settings set by policy to an accepted value"
        } elseif ($av.Count -gt 0) {
            # The expected state is that an assigned policy CONFIGURES Defender Antivirus:
            # real-time protection, cloud-delivered protection and PUA protection. The
            # policy existing is verified; the settings come from the collector's read.
            $read = $avRead
            $maps = @($read | ForEach-Object { Get-TPObjectField -Item $_ -Key 'AvSettings' -Default $null } | Where-Object { $null -ne $_ })
            $verified = @("$($av.Count) assigned Microsoft Defender Antivirus policy(ies).")
            $short = @(); $unknown = @()
            if ($read.Count -lt $av.Count) {
                $unknown += "the antivirus settings of $($av.Count - $read.Count) of $($av.Count) assigned policy(ies) could not be read, so real-time, cloud-delivered and PUA protection are not established."
            }
            # While the approved benchmark is in force it IS the expected state, so
            # three settings passing cannot stand for it: without every stored value
            # (a results file from before that read) the control is not assessed.
            if ($null -ne $baseline) {
                $unknown += "the $($baseline.Name) ($($baseline.Profile)), the approved standard, because the assigned policies' setting values were not stored (a results file from before that read, or a value read that did not complete); only real-time, cloud-delivered and PUA protection were judged."
            }
            if ($maps.Count -gt 0) {
                $label = @{ RealTimeProtection = 'Real-time protection'; CloudProtection = 'Cloud-delivered protection'; PuaProtection = 'PUA protection' }
                foreach ($row in @(Test-TPAvSettingSet -SettingMaps $maps)) {
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
            Add-TPExpectedStateFinding -ControlId 'INT-1.5' -Control $c -FrameworkIds (& $cit 'INT-1.5') -Verified $verified -Shortfalls $short -NotEstablished $unknown `
                -CurrentValue "$($av.Count) AV policies assigned" -RequiredValue 'An assigned Defender Antivirus policy with real-time, cloud-delivered and PUA protection on'
        } else {
            Add-TPFinding -ControlId 'INT-1.5' -State 'Gap' -Category 'Endpoint' -Title $c.Title -Severity $c.Severity -FrameworkIds (& $cit 'INT-1.5') `
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
function Get-TPEnrolledPlatformCount {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw, [Parameter(Mandatory)] [string] $Pattern)
    if (-not (Test-TPSectionCollected $Raw 'OSComplianceSummary')) { return $null }
    $sum = Get-TPObjectField -Item $Raw.Data -Key 'OSComplianceSummary' -Default $null
    $by  = Get-TPObjectField -Item $sum -Key 'ByPlatform' -Default $null
    if ($null -eq $by) { return $null }
    $names = if ($by -is [System.Collections.IDictionary]) { @($by.Keys) } else { @($by.PSObject.Properties.Name) }
    $n = 0
    foreach ($k in $names) { if ([string]$k -match $Pattern) { $n += [int](Get-TPObjectField -Item $by -Key $k -Default 0) } }
    return $n
}

# One line naming what IS enrolled, for a platform with none.
function Get-TPEnrolledPlatformSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw)
    $sum = Get-TPObjectField -Item $Raw.Data -Key 'OSComplianceSummary' -Default $null
    $by  = Get-TPObjectField -Item $sum -Key 'ByPlatform' -Default $null
    if ($null -eq $by) { return 'no managed devices' }
    $names = if ($by -is [System.Collections.IDictionary]) { @($by.Keys) } else { @($by.PSObject.Properties.Name) }
    $parts = @($names | Sort-Object | ForEach-Object { "$([int](Get-TPObjectField -Item $by -Key $_ -Default 0)) $_" })
    if ($parts.Count -eq 0) { return 'no managed devices' }
    return ($parts -join ', ')
}

# Judges the non-compliance actions of assigned compliance policies. An action
# counts when it does something to the device or its access: block (Intune's
# "mark device noncompliant", with its grace period), retire, wipe, remoteLock,
# removeResourceAccessProfiles. notification, pushNotification and noAction only
# tell someone. A policy whose actions were not read (ActionsRead absent or
# $false: an older results file, or a tenant that refused the expand) is Unread,
# never lacking. Acting carries a phrase per policy for the Detail.
function Get-TPComplianceActionVerdict {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()] [object[]] $Policies)
    $acting  = [System.Collections.Generic.List[string]]::new()
    $lacking = [System.Collections.Generic.List[string]]::new()
    $unread  = [System.Collections.Generic.List[string]]::new()
    $consequential = @('block', 'retire', 'wipe', 'remoteLock', 'removeResourceAccessProfiles')
    foreach ($p in @($Policies)) {
        if ($null -eq $p) { continue }
        $name = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '')
        if (-not $name) { $name = [string](Get-TPObjectField -Item $p -Key 'Name' -Default '(unnamed policy)') }
        $read = Get-TPObjectField -Item $p -Key 'ActionsRead' -Default $null
        if ($read -ne $true) { $unread.Add($name); continue }
        $acts = @(Get-TPObjectField -Item $p -Key 'NonComplianceActions' -Default @() | Where-Object { $null -ne $_ })
        $hits = @($acts | Where-Object { ([string](Get-TPObjectField -Item $_ -Key 'ActionType' -Default '')) -in $consequential })
        if ($hits.Count -eq 0) { $lacking.Add($name); continue }
        $parts = foreach ($h in $hits) {
            $t = [string](Get-TPObjectField -Item $h -Key 'ActionType' -Default '')
            $g = Get-TPObjectField -Item $h -Key 'GracePeriodHours' -Default $null
            $label = if ($t -eq 'block') { 'mark noncompliant' } else { $t }
            if ($null -ne $g -and [int]$g -gt 0) { "$label after $([int]$g) h" } else { "$label immediately" }
        }
        $acting.Add("$name ($(@($parts | Sort-Object -Unique) -join ', '))")
    }
    return @{ Acting = @($acting.ToArray()); Lacking = @($lacking.ToArray()); Unread = @($unread.ToArray()) }
}

function Select-TPAssignedPolicies {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Policies)
    return @(@($Policies) | Where-Object { $null -ne $_ -and (Get-TPObjectField -Item $_ -Key 'IsAssigned' -Default $null) -ne $false })
}

# Scored endpoint-security policies of one bucket, assigned only, with a
# phrase naming unassigned ones left out.
function Get-TPIntuneBucketState {
    [CmdletBinding()]
    param([AllowNull()] $Raw, [Parameter(Mandatory)] [string] $Section)
    $all = @(Get-TPObjectField -Item $Raw.Data -Key $Section -Default @() | Where-Object { $null -ne $_ })
    $assigned = @(Select-TPAssignedPolicies $all)
    $note = if ($all.Count -gt $assigned.Count) { " $($all.Count - $assigned.Count) unassigned policy(ies) were not counted." } else { '' }
    return @{ Assigned = $assigned; Note = $note }
}

# ── INT-2.1 Endpoint Detection and Response Deployed ─────────────────────────
function Test-TPControlIntuneEDR {
    [CmdletBinding()] param()
    $cid = 'INT-2.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'EndpointDetectionPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'EndpointDetectionPolicies was not collected; not assessed.'
        return
    }
    $st = Get-TPIntuneBucketState -Raw $int -Section 'EndpointDetectionPolicies'
    if ($st.Assigned.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($st.Assigned.Count) assigned Microsoft Defender for Endpoint onboarding (EDR) policy(ies) deployed via Intune.$($st.Note)"
        return
    }

    # No Intune-managed Defender for Endpoint onboarding policy. A client on a
    # third-party EDR (Cortex XDR, CrowdStrike, SentinelOne, ...) is declared
    # per client with -ThirdPartyEDR / clients.json ThirdPartyEDR, or MSP-wide
    # with EdrStack in Config/branding.psd1; Set-TPThirdPartyEdr then takes
    # this check out of the score as "declared, not verified". It used to be
    # scored Satisfied straight from the branding declaration — a pass on a
    # claim nothing verified — and Partial (half credit) for a manual review
    # when nothing was declared.
    Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
        -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
        -Detail 'No Microsoft Defender for Endpoint onboarding policy is deployed via Intune. If this client runs a third-party EDR instead (Cortex XDR, CrowdStrike, SentinelOne, ...), declare it with -ThirdPartyEDR or ThirdPartyEDR in clients.json: the check is then reported as covered by that product (declared, not verified) and not scored.' `
        -CurrentValue 'No Intune-managed Defender for Endpoint onboarding policy' `
        -RequiredValue 'EDR onboarding deployed to every managed endpoint' `
        -Remediation $ctrl.Remediation
}

# ── INT-2.2 Attack Surface Reduction Rules Enabled ───────────────────────────
function Test-TPControlIntuneASR {
    [CmdletBinding()] param()
    $cid = 'INT-2.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'ASRPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ASRPolicies was not collected; not assessed.'
        return
    }
    $st = Get-TPIntuneBucketState -Raw $int -Section 'ASRPolicies'
    if ($st.Assigned.Count -gt 0) {
        # The expected state is the approved NRG ASR rule set, every rule in the mode
        # its entry requires (Block, or Audit where the approved benchmark accepts it). The policy existing is verified; the rule modes come from the settings
        # read (collector), and the REQUIRED list is an operator-approved file (an empty
        # list means no standard is approved). Nothing is inferred: an unread mode is unknown, never Block.
        $asrPolicies = @($st.Assigned)
        $read   = @($asrPolicies | Where-Object { (Get-TPObjectField -Item $_ -Key 'AsrSettingsStatus' -Default '') -eq 'Read' })
        $modeMaps = @($read | ForEach-Object { Get-TPObjectField -Item $_ -Key 'AsrRuleModes' -Default $null } | Where-Object { $null -ne $_ })
        $allModes = @($modeMaps | ForEach-Object { @($_.Values) })
        $modeSummary = if ($allModes.Count -gt 0) { ($allModes | Group-Object | Sort-Object Name | ForEach-Object { "$($_.Count) in $($_.Name)" }) -join ', ' } else { '' }
        $required = @(Get-TPAsrRequiredRules)
        $verified = "Verified: $($st.Assigned.Count) assigned Attack Surface Reduction Rules policy(ies).$($st.Note)"
        if ($read.Count -lt $asrPolicies.Count) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "$verified Not assessed: the rule settings of $($asrPolicies.Count - $read.Count) of $($asrPolicies.Count) assigned policy(ies) could not be read, so which rules are configured and in what mode is not established.$(if ($modeSummary) { " Read so far: $modeSummary." })" `
                -CurrentValue "$($st.Assigned.Count) assigned ASR policy(ies); rule settings not fully read" `
                -RequiredValue 'The approved NRG ASR rule set with every rule in its required mode'
        } elseif ($required.Count -eq 0) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "$verified Rule modes read: $(if ($modeSummary) { $modeSummary } else { 'no ASR rule settings found in the assigned policies' }). Not assessed: whether the approved NRG rule set is in its required modes, because no required rule list is approved (Config/asr-required-rules.json is empty)." `
                -CurrentValue "$($st.Assigned.Count) assigned ASR policy(ies); $(if ($modeSummary) { $modeSummary } else { 'no rule settings found' })" `
                -RequiredValue 'The approved NRG ASR rule set with every rule in its required mode'
        } else {
            $judge = Test-TPAsrRuleSet -RuleModeMaps $modeMaps -Required $required
            if ($judge.NotMet.Count -eq 0) {
                $audit = @($judge.Rows | Where-Object { $_.Mode -ne 'Block' })
                $auditNote = if ($audit.Count) { " $($audit.Count) of them in $(@($audit | ForEach-Object { $_.Mode } | Select-Object -Unique) -join '/') mode, which their approved entry accepts: $(($audit | ForEach-Object { $_.Name }) -join '; ')." } else { '' }
                Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
                    -Detail "All $($judge.Required) required ASR rule(s) are in their required mode in the assigned policy(ies).$auditNote$($st.Note)"
            } else {
                $list = ($judge.NotMet | ForEach-Object { "$($_.Name) ($($_.Mode); requires $(@($_.Accept) -join ' or '))" }) -join '; '
                $state = if ($judge.Met -gt 0) { 'Partial' } else { 'Gap' }
                Add-TPFinding -ControlId $cid -State $state -Category $ctrl.Category -Title $ctrl.Title -Severity $(if ($state -eq 'Gap') { $ctrl.Severity } else { 'Medium' }) -FrameworkIds $cit `
                    -Detail "$verified Shortfall: $($judge.NotMet.Count) of $($judge.Required) required ASR rule(s) are not in their required mode: $list." `
                    -CurrentValue "$($judge.Met) of $($judge.Required) required rules in their required mode" `
                    -RequiredValue 'Every approved NRG ASR rule in its required mode' -Remediation $ctrl.Remediation `
                    -AffectedObjects @($judge.NotMet | ForEach-Object { [ordered]@{ Rule = $_.Name; Mode = $_.Mode; Requires = (@($_.Accept) -join ' or ') } })
            }
        }
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Attack Surface Reduction Rules policy in Intune (Device Control, Exploit Protection and other templates in the same family are not ASR rules).$($st.Note) ASR rules block commodity malware delivery such as Office macro abuse and credential theft." -Remediation $ctrl.Remediation
    }
}

# The stored Settings Catalog values of one endpoint-security policy (SettingValues,
# keyed by lower-case setting definition id, from Get-TPAvSettingValues) whose id
# matches $Pattern, and whether they were read in full. A policy from the legacy
# intents endpoint, an older results file or a failed read carries no values:
# Read = $false, never "nothing set".
function Get-TPIntunePolicySettingMatches {
    [CmdletBinding()]
    param([AllowNull()] $Policy, [Parameter(Mandatory)] [string] $Pattern, [string] $Exclude)
    $status = [string](Get-TPObjectField -Item $Policy -Key 'SettingsStatus' -Default '')
    $values = Get-TPObjectField -Item $Policy -Key 'SettingValues' -Default $null
    $out = [ordered]@{ Read = ($status -eq 'Read' -and $null -ne $values); Values = @() }
    if ($null -eq $values -or $status -notin @('Read', 'Partial')) { return $out }
    $keys = if ($values -is [System.Collections.IDictionary]) { @($values.Keys) } else { @($values.PSObject.Properties.Name) }
    foreach ($k in $keys) {
        $id = ([string]$k).ToLowerInvariant()
        if ($id -notmatch $Pattern) { continue }
        if ($Exclude -and $id -match $Exclude) { continue }
        $out.Values += ([string](Get-TPObjectField -Item $values -Key $k -Default '')).ToLowerInvariant()
    }
    return $out
}

# INT-2.3: each Windows Firewall network profile across the assigned Firewall policies.
# Firewall CSP MdmStore/<Domain|Private|Public>Profile/EnableFirewall, matched by the
# CSP node at the end of the setting definition id (Microsoft publishes no Graph sample
# of the Firewall template's ids; the Hyper-V firewall nodes share the leaf name and are
# excluded). A choice value ending _true turns the profile on, _false turns it off.
#   On           some read policy turns it on, none turns it off, every policy read
#   Off          some policy turns it off (a shortfall whatever else is unread)
#   NotSet       every policy read and none sets it (the not-configured rule: Windows
#                turns the firewall on by default, but nothing enforces it)
#   NotEstablished  a policy's settings were not read, or a value is not one recognized
function Get-TPFirewallProfileStates {
    [CmdletBinding()]
    param([object[]] $Policies)
    $name = { param($p) $n = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default ''); if ($n) { $n } else { [string](Get-TPObjectField -Item $p -Key 'Id' -Default 'unnamed policy') } }
    $rows = @()
    foreach ($prof in 'Domain', 'Private', 'Public') {
        $on = @(); $off = @(); $odd = @(); $unread = @()
        foreach ($p in @($Policies)) {
            $m = Get-TPIntunePolicySettingMatches -Policy $p -Pattern "mdmstore_$($prof.ToLowerInvariant())profile_enablefirewall$" -Exclude 'hypervvmsettings'
            if (-not $m.Read) { $unread += (& $name $p) }
            foreach ($v in $m.Values) {
                if ($v -match '_true$') { $on += (& $name $p) }
                elseif ($v -match '_false$') { $off += (& $name $p) }
                else { $odd += "$(& $name $p) ($v)" }
            }
        }
        $state = if ($off.Count) { 'Off' } elseif ($odd.Count -or $unread.Count) { 'NotEstablished' } elseif ($on.Count) { 'On' } else { 'NotSet' }
        $rows += [pscustomobject]@{ Profile = $prof; State = $state; On = @($on | Select-Object -Unique); Off = @($off | Select-Object -Unique); Unrecognized = $odd; Unread = $unread }
    }
    return $rows
}

# ── INT-2.3 Firewall Policy Deployed via Intune ───────────────────────────────
function Test-TPControlIntuneFirewall {
    [CmdletBinding()] param()
    $cid = 'INT-2.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Intune endpoint security data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'FirewallPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'FirewallPolicies was not collected; not assessed.'
        return
    }
    $st = Get-TPIntuneBucketState -Raw $int -Section 'FirewallPolicies'
    if ($st.Assigned.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Windows Firewall policy in Intune (a firewall RULES policy alone does not turn the firewall on).$($st.Note) Endpoint firewall configuration is unmanaged." -Remediation $ctrl.Remediation
        return
    }
    # A Firewall policy existing is not the firewall turned on: a policy that sets
    # Enable <profile> Network Firewall = False was Satisfied. Each of the domain,
    # private and public profiles is judged from the assigned policies' settings.
    $rows = @(Get-TPFirewallProfileStates -Policies $st.Assigned)
    $verified = @(); $short = @(); $notEst = @()
    foreach ($r in $rows) {
        switch ($r.State) {
            'On'     { $verified += "The $($r.Profile) profile firewall is turned on ($($r.On -join ', '))." }
            'Off'    { $short += "The $($r.Profile) profile firewall is turned off by $($r.Off -join ', ')." }
            'NotSet' { $short += "No assigned policy turns on the $($r.Profile) profile firewall (Windows turns it on by default, but nothing enforces it, so it can be turned off on the device)." }
            default  {
                $why = @()
                if ($r.Unread.Count) { $why += "the settings of $($r.Unread -join ', ') were not read" }
                if ($r.Unrecognized.Count) { $why += "a value is not one this assessment recognizes: $($r.Unrecognized -join ', ')" }
                $notEst += "Whether the $($r.Profile) profile firewall is turned on, because $($why -join '; ')."
            }
        }
    }
    # The policy count is context, never a verified component on its own: a policy that
    # turns nothing on must not lift a Gap to Partial.
    $lead = "$($st.Assigned.Count) assigned Windows Firewall policy(ies).$($st.Note)"
    if ($verified.Count) { $verified = @($lead) + $verified }
    elseif ($short.Count) { $short[0] = "$lead $($short[0])" }
    elseif ($notEst.Count) { $notEst[0] = "$lead $($notEst[0])" }
    $cur = ($rows | ForEach-Object { "$($_.Profile): $($_.State)" }) -join '; '
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $notEst `
        -CurrentValue $cur -RequiredValue 'An assigned Windows Firewall policy turning on the domain, private and public network firewall (Enable Network Firewall = True for each)' `
        -AffectedObjects @($rows | Where-Object { $_.State -ne 'On' } | ForEach-Object { [ordered]@{ Profile = $_.Profile; State = $_.State; TurnedOffBy = ($_.Off -join ', ') } })
}

# ── INT-2.4 Disk Encryption Compliance for macOS ─────────────────────────────
function Test-TPControlIntuneMacEncryption {
    [CmdletBinding()] param()
    $cid = 'INT-2.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune compliance data not collected'; return }
    if (-not (Test-TPSectionCollected $int 'CompliancePolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'CompliancePolicies was not collected; not assessed.'; return
    }
    $macDevices  = Get-TPEnrolledPlatformCount -Raw $int -Pattern '^macOS'
    $macPolicies = @(Select-TPAssignedPolicies @(@(Get-TPObjectField -Item $int.Data -Key 'CompliancePolicies' -Default @()) | Where-Object { (Get-TPObjectField -Item $_ -Key 'Platform') -match 'macOS|Mac' }))
    if ($macDevices -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No macOS devices are enrolled in Intune (enrolled: $(Get-TPEnrolledPlatformSummary -Raw $int)), so no Mac is governed by a compliance policy either way."
        return
    }
    if ($macPolicies.Count -eq 0) {
        if ($macDevices -gt 0) {
            Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "$macDevices macOS device(s) are enrolled, but no assigned macOS compliance policy requires FileVault. A lost or stolen Mac exposes whatever it holds." `
                -CurrentValue "$macDevices Mac(s), no macOS compliance policy" -RequiredValue 'Assigned macOS compliance policy requiring FileVault (Require encryption of data storage)' -Remediation $ctrl.Remediation
        } else {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail 'No assigned macOS compliance policy, and the managed-device inventory was not read, so whether any Mac is enrolled is unknown. Not assessed.'
        }
        return
    }
    # FileVault is storageRequireEncryption. System Integrity Protection, which
    # used to be accepted as well, is unrelated to disk encryption.
    $encRequired = @($macPolicies | Where-Object { (Get-TPObjectField -Item $_ -Key 'StorageRequireEncryption') -eq $true }).Count -gt 0
    if ($encRequired) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'macOS compliance policy requires FileVault encryption.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'macOS compliance policy does not require FileVault encryption. Stolen Macs expose all organizational data.' -Remediation $ctrl.Remediation
    }
}

# ── INT-2.5 Windows Update Compliance Policy ─────────────────────────────────
function Test-TPControlIntuneWindowsUpdate {
    [CmdletBinding()] param()
    $cid = 'INT-2.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune compliance data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'UpdatePolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'UpdatePolicies was not collected; not assessed.'
        return
    }
    $winUpdatePolicies = @(Select-TPAssignedPolicies @(Get-TPObjectField -Item $int.Data -Key 'UpdatePolicies' -Default @()))
    if ($winUpdatePolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($winUpdatePolicies.Count) assigned Windows Update for Business ring(s)."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Windows Update for Business policy found in Intune. Endpoints may not receive security updates on a managed schedule. Verify via Windows Update rings.' -Remediation $ctrl.Remediation
    }
}

# ── INT-3.1 Device Enrollment Restrictions Configured ────────────────────────
function Test-TPControlIntuneEnrollmentRestrictions {
    [CmdletBinding()] param()
    $cid = 'INT-3.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-TPSectionCollected $int 'EnrollmentRestrictions')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Enrollment restrictions were not collected; not assessed.'; return
    }
    # Every tenant has the default restrictions ("All users and all devices",
    # priority 0), which allow every platform and personal devices. Their
    # presence is not a restriction; a block inside one — default or custom —
    # is. Results collected before the per-platform blocks were read carry no
    # Restrictions field and are not assessed.
    $rows = @(Get-TPObjectField -Item $int.Data -Key 'EnrollmentRestrictions' -Default @() | Where-Object { $null -ne $_ })
    $platformRows = @($rows | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Type' -Default '') -match 'PlatformRestriction' })
    if (@($platformRows | Where-Object { $null -eq (Get-TPObjectField -Item $_ -Key 'Restrictions' -Default $null) }).Count -gt 0 -or $platformRows.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The platform restriction settings were not collected; not assessed.'; return
    }
    # Windows Mobile is retired and Intune blocks it in the default
    # configuration of every tenant, so that block restricts nothing anyone
    # enrolls. A live tenant passed on "windowsMobile: platform blocked" alone.
    $blocks = @($platformRows | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'Restrictions' -Default @()) } | Where-Object {
        $_ -and [string]$_.Platform -ne 'windowsMobile' -and ($_.PlatformBlocked -or $_.PersonalBlocked -or $_.OsMinimumVersion) })
    if ($blocks.Count -gt 0) {
        $what = @($blocks | ForEach-Object { "$($_.Platform): $(@(if ($_.PlatformBlocked) { 'platform blocked' }; if ($_.PersonalBlocked) { 'personal devices blocked' }; if ($_.OsMinimumVersion) { "min OS $($_.OsMinimumVersion)" }) -join ', ')" })
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Enrollment is restricted: $($what -join '; ')."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'Enrollment restrictions are at their defaults: every platform may enroll, personal devices included, with no minimum OS version. Any user can enroll any device and have it treated as managed.' `
            -CurrentValue 'Default restrictions only (nothing blocked)' -RequiredValue 'Block personal enrollment and unused platforms, set minimum OS versions' -Remediation $ctrl.Remediation
    }
}

# ── INT-3.2 Mobile App Configuration Policies Deployed ───────────────────────
function Test-TPControlIntuneAppConfig {
    [CmdletBinding()] param()
    $cid = 'INT-3.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-AppProtection'
    if (-not $int -or -not $int.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Intune app protection data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'AppConfigPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AppConfigPolicies was not collected; not assessed.'
        return
    }
    $appConfig = @($int.Data['AppConfigPolicies'] ?? @())
    if ($appConfig.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($appConfig.Count) app configuration policy(ies) deployed."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No app configuration policies found. Managed apps may use default settings without security baseline configuration.' `
            -Remediation $ctrl.Remediation
    }
}

# ── INT-3.3 Conditional Launch Policies Configured ───────────────────────────
function Test-TPControlIntuneConditionalLaunch {
    [CmdletBinding()] param()
    $cid = 'INT-3.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-AppProtection'
    if (-not $int -or -not $int.Success -or -not (Test-TPSectionCollected $int 'AppProtectionPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'App protection policies were not collected; not assessed.'; return
    }
    # Jailbreak / root blocking and the PIN-retry and offline-wipe limits
    # are on by DEFAULT in every app protection policy, so their presence
    # proved nothing (every policy passed). The setting an admin must choose
    # is a minimum OS version for the apps to open.
    $prot = @(Select-TPAssignedPolicies @(@(Get-TPObjectField -Item $int.Data -Key 'AppProtectionPolicies' -Default @()) | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Type' -Default '') -match 'ManagedAppProtection$' }))
    if ($prot.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No assigned app protection policy exists, so no conditional launch check applies to corporate apps on mobile devices.' -Remediation $ctrl.Remediation
        return
    }
    $withOs = @($prot | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'MinimumRequiredOsVersion' -Default '') })
    if ($withOs.Count -eq $prot.Count) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Every assigned app protection policy ($($prot.Count)) blocks apps on devices below a minimum OS version, in addition to the default jailbreak / root block."
    } elseif ($withOs.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($withOs.Count) of $($prot.Count) assigned app protection policies set a minimum OS version; apps under the others open on any OS version." -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No assigned app protection policy sets a minimum OS version, so corporate apps open on out-of-support, unpatched mobile OS versions (only the default jailbreak / root block applies).' `
            -CurrentValue "$($prot.Count) policy(ies), none with a minimum OS version" -RequiredValue 'Conditional launch: minimum OS version (block access)' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.1 Windows LAPS Configured ──────────────────────────────────────────
# Each assigned Windows LAPS policy's BackupDirectory (LAPS CSP Policies/BackupDirectory:
# 0 Disabled, the default when not set; 1 Microsoft Entra ID only; 2 Active Directory
# only), matched by the CSP node at the end of the setting definition id and the value
# id's trailing number (Microsoft publishes no Graph sample of the LAPS template's ids).
# A policy that backs up nothing was Satisfied because it existed. Only Microsoft Entra
# ID is credited: this control's expected state is the password escrowed in Entra ID.
function Test-TPControlIntuneWindowsLAPS {
    [CmdletBinding()] param()
    $cid = 'INT-4.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Intune data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'LAPSPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'LAPSPolicies was not collected; not assessed.'
        return
    }
    $st = Get-TPIntuneBucketState -Raw $int -Section 'LAPSPolicies'
    if ($st.Assigned.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Windows LAPS policy (Account Protection policies such as Credential Guard are not LAPS).$($st.Note) If endpoints share a local admin password, one compromise opens every endpoint." -Remediation $ctrl.Remediation
        return
    }
    $entra = @(); $short = @(); $notEst = @(); $rows = @()
    foreach ($p in $st.Assigned) {
        $n = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '')
        if (-not $n) { $n = [string](Get-TPObjectField -Item $p -Key 'Id' -Default 'unnamed policy') }
        $m = Get-TPIntunePolicySettingMatches -Policy $p -Pattern 'laps_policies_backupdirectory$'
        $vals = @($m.Values | Select-Object -Unique)
        $state = if ($vals.Count -gt 1) { 'Unrecognized' }
                 elseif ($vals.Count -eq 1 -and $vals[0] -match '_1$') { 'EntraID' }
                 elseif ($vals.Count -eq 1 -and $vals[0] -match '_2$') { 'ActiveDirectory' }
                 elseif ($vals.Count -eq 1 -and $vals[0] -match '_0$') { 'Disabled' }
                 elseif ($vals.Count -eq 1) { 'Unrecognized' }
                 elseif ($m.Read) { 'NotSet' }
                 else { 'NotRead' }
        $rows += [ordered]@{ Policy = $n; BackupDirectory = $state }
        switch ($state) {
            'EntraID'         { $entra += $n }
            'ActiveDirectory' { $short += "$n backs the password up to Active Directory, not Microsoft Entra ID." }
            'Disabled'        { $short += "$n sets Backup Directory to Disabled, so the managed password is not backed up anywhere." }
            'NotSet'          { $short += "$n does not set Backup Directory, which Windows LAPS treats as Disabled (the password is not backed up)." }
            'Unrecognized'    { $notEst += "The Backup Directory of $n, because its value ($($vals -join ', ')) is not one this assessment recognizes." }
            default           { $notEst += "The Backup Directory of $n, because the policy's settings were not read (a legacy endpoint-security policy, a failed read, or a results file from before the settings were read)." }
        }
    }
    # The policy count is context, never a verified component on its own: a policy that
    # backs nothing up must not lift a Gap to Partial.
    $lead = "$($st.Assigned.Count) assigned Windows LAPS policy(ies).$($st.Note)"
    $verified = @()
    if ($entra.Count) { $verified = @($lead, "Backed up to Microsoft Entra ID: $($entra -join ', ').") }
    elseif ($short.Count) { $short[0] = "$lead $($short[0])" }
    elseif ($notEst.Count) { $notEst[0] = "$lead $($notEst[0])" }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $notEst `
        -CurrentValue (($rows | ForEach-Object { "$($_.Policy): $($_.BackupDirectory)" }) -join '; ') `
        -RequiredValue 'Every assigned Windows LAPS policy backs the password up to Microsoft Entra ID (Backup Directory = 1)' `
        -AffectedObjects @($rows | Where-Object { $_.BackupDirectory -ne 'EntraID' })
}

# ── INT-4.2 Windows Hello for Business Deployed ───────────────────────────────
function Test-TPControlIntuneWindowsHello {
    [CmdletBinding()] param()
    $cid = 'INT-4.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-TPSectionCollected $int 'WindowsHelloPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Windows Hello for Business enrollment configuration was not collected; not assessed.'; return
    }
    # Every tenant has the default WHfB enrollment configuration; its State
    # (enabled / disabled / notConfigured) is the setting. Its mere presence
    # passed every tenant.
    $rows = @(Get-TPObjectField -Item $int.Data -Key 'WindowsHelloPolicies' -Default @() | Where-Object { $null -ne $_ })
    $states = @($rows | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') })
    if (@($states | Where-Object { $_ -eq 'enabled' }).Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Windows Hello for Business is enabled in the Intune enrollment configuration — devices are provisioned with phishing-resistant sign-in.'
    } elseif (@($states | Where-Object { $_ }).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The Windows Hello for Business enrollment state was not returned; not assessed.'
    } else {
        # Never a Gap from this read alone. Microsoft's own guidance (Configure
        # Windows Hello for Business, Intune section): the tenant-wide policy
        # "is only applied at enrollment time", "applies to all devices", and
        # "for this reason, the policy is usually disabled and Windows Hello for
        # Business is enabled using a policy targeted to a security group" (an
        # endpoint-security Account protection profile, or the settings
        # catalog). This assessment does not read those policies yet, so a
        # disabled or unconfigured tenant policy is the documented default of a
        # tenant that enables Windows Hello elsewhere, not evidence that it is
        # off. Scoring it as a Gap was a false Gap on every tenant following
        # Microsoft's pattern; the limit is recorded in Config/evidence-limits.json.
        $how = if ($states -contains 'disabled') { 'disabled' } else { 'not configured' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Windows Hello for Business is $how in the tenant-wide Intune enrollment configuration. Microsoft's documented pattern leaves that policy disabled and enables Windows Hello for Business through an endpoint-security Account protection or settings-catalog policy targeted to a security group, which this assessment does not read, so whether Windows Hello for Business is enabled for enrolled devices is not established; not assessed. Confirm in Intune > Endpoint security > Account protection (or the settings catalog) that a policy with Use Windows Hello for Business = Enabled is assigned to the users or devices in scope." `
            -CurrentValue "Tenant-wide enrollment policy state = $($states -join ', ')"
    }
}

# ── INT-4.3 Update Compliance / Windows Update for Business Reports ───────────
function Test-TPControlIntuneUpdateCompliance {
    [CmdletBinding()] param()
    $cid = 'INT-4.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-TPSectionCollected $int 'CompliancePolicies') -or -not (Test-TPSectionCollected $int 'OSComplianceSummary')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Compliance policies or the managed-device summary were not collected; not assessed.'; return
    }
    # Two halves. A minimum OS version must be a compliance rule; without one
    # a device's "compliant" state says nothing about its OS version, which
    # is what was reported as "OS-version compliant" before.
    $policies = @(Select-TPAssignedPolicies @(Get-TPObjectField -Item $int.Data -Key 'CompliancePolicies' -Default @()))
    $hasKey = { param($p) if ($p -is [System.Collections.IDictionary]) { $p.Contains('OsMinimumVersion') } else { [bool]$p.PSObject.Properties['OsMinimumVersion'] } }
    if ($policies.Count -gt 0 -and @($policies | Where-Object { & $hasKey $_ }).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Minimum OS versions in compliance policies were not collected; not assessed.'; return
    }
    $withMin = @($policies | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'OsMinimumVersion' -Default '') })
    if ($withMin.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No assigned compliance policy sets a minimum OS version, so a device on an out-of-support OS is still compliant.' `
            -RequiredValue 'Minimum OS version in compliance policies, and at least 90% of devices compliant' -Remediation $ctrl.Remediation
        return
    }
    $total = [int](Get-TPNestedProperty -Object $int -Path 'Data.OSComplianceSummary.TotalCount' -Default 0)
    $ok    = [int](Get-TPNestedProperty -Object $int -Path 'Data.OSComplianceSummary.CompliantCount' -Default 0)
    if ($total -le 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "$($withMin.Count) compliance policy(ies) set a minimum OS version, but no managed devices were returned to measure compliance against."
        return
    }
    $pct = [int][math]::Floor($ok * 100 / $total)
    if ($pct -ge 90) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($withMin.Count) compliance policy(ies) set a minimum OS version, and $pct% of managed devices ($ok/$total) are compliant with their policies."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Only $pct% of managed devices ($ok/$total) are compliant with their compliance policies (minimum OS version among the rules); $($total - $ok) are not." -CurrentValue "$pct% compliant" -RequiredValue 'At least 90% compliant' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.4 Mobile Device Compliance Policy Requires PIN/Biometric ────────────
function Test-TPControlIntuneMobilePIN {
    [CmdletBinding()] param()
    $cid = 'INT-4.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success -or -not (Test-TPSectionCollected $int 'CompliancePolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'CompliancePolicies was not collected; not assessed.'; return
    }
    $mobileDevices = Get-TPEnrolledPlatformCount -Raw $int -Pattern '^(iOS|iPadOS|Android)'
    if ($mobileDevices -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No iOS, iPadOS or Android devices are enrolled in Intune (enrolled: $(Get-TPEnrolledPlatformSummary -Raw $int)), so a mobile compliance setting governs no device. Phones reaching company data without enrolling are covered by app protection (INT-1.4)."
        return
    }
    $mobile = @(Select-TPAssignedPolicies @(@(Get-TPObjectField -Item $int.Data -Key 'CompliancePolicies' -Default @()) | Where-Object { (Get-TPObjectField -Item $_ -Key 'Platform') -match 'ios|android' }))
    if ($mobile.Count -eq 0) {
        if ($mobileDevices -gt 0) {
            Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "$mobileDevices mobile device(s) are enrolled, but no assigned iOS or Android compliance policy requires a passcode." -Remediation $ctrl.Remediation
        } else {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail 'No assigned iOS or Android compliance policy, and the managed-device inventory was not read, so whether any mobile device is enrolled is unknown. Not assessed.'
        }
        return
    }
    # iOS names it passcodeRequired; Android passwordRequired. Reading only
    # passwordRequired failed every iOS-only fleet.
    $req = { param($p) (Get-TPObjectField -Item $p -Key 'PasscodeRequired' -Default $null) -eq $true -or (Get-TPObjectField -Item $p -Key 'PasswordRequired' -Default $null) -eq $true }
    $platforms = @($mobile | ForEach-Object { if ((Get-TPObjectField -Item $_ -Key 'Platform') -match 'ios') { 'iOS' } else { 'Android' } } | Sort-Object -Unique)
    $covered = @($platforms | Where-Object { $pl = $_; @($mobile | Where-Object { ((Get-TPObjectField -Item $_ -Key 'Platform') -match ($(if ($pl -eq 'iOS') { 'ios' } else { 'android' }))) -and (& $req $_) }).Count -gt 0 })
    if ($covered.Count -eq $platforms.Count) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Mobile compliance policies require a device passcode on $($platforms -join ' and ')."
    } elseif ($covered.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "A passcode is required on $($covered -join ', ') but not on $(@($platforms | Where-Object { $_ -notin $covered }) -join ', ')." -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Mobile compliance policies do not require a device passcode. A lost or stolen unlocked device exposes corporate data.' -Remediation $ctrl.Remediation
    }
}

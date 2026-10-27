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

# ── INT-2.6 Office Macro and Active-Content Hardening Deployed ────────────────
# The expected state is the approved core of the CIS Microsoft Intune for Office
# Benchmark v1.1.0, Level 1 (Config/cis-intune-office-macro.json; approval in
# tp-standards.json IntuneOfficeMacroBaseline): every encoded setting set, by the
# assigned Settings Catalog policies that configure Office, to the state the
# benchmark requires. Not set is a shortfall (the not-configured rule; Office's
# default is named, never credited). Administrative Templates policies are listed,
# not read: a tenant whose Office settings live only there is not assessed, never a
# Gap, and one that holds Office settings beside a Settings Catalog policy leaves
# every setting the catalog does not meet unestablished (a value there can stand in
# for or conflict with it). Office cloud policy service and on-premises Group Policy
# are not visible to Graph at all; the Gap and the pass both say so.
function Test-TPControlIntuneOfficeMacro {
    [CmdletBinding()] param()
    $cid = 'INT-2.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Intune endpoint security data not collected'; return }
    $data = Get-TPObjectField -Item $int -Key 'Data' -Default $null
    # A results file from before the Office read carries no OfficePolicies section.
    if (-not (Test-TPFieldPresent -Item $data -Key 'OfficePolicies') -or -not (Test-TPSectionCollected $int 'OfficePolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'OfficePolicies was not collected; not assessed. The Office settings of the assigned Settings Catalog policies were not read (the read failed, or a results file from before this read).'
        return
    }
    $baseline = Get-TPIntuneOfficeMacroBaseline
    if ($null -eq $baseline) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Not assessed: the Office macro and active-content settings are not judged because no Office macro configuration standard is approved (Config/tp-standards.json IntuneOfficeMacroBaseline is empty or names another benchmark version than Config/cis-intune-office-macro.json).'
        return
    }
    $pname = { param($p) $n = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default ''); if ($n) { $n } else { [string](Get-TPObjectField -Item $p -Key 'Id' -Default 'unnamed policy') } }
    $office = @(Select-TPAssignedPolicies @(Get-TPObjectField -Item $data -Key 'OfficePolicies' -Default @()))
    $read   = @($office | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'OfficeSettingsStatus' -Default '') -eq 'Read' })
    $unread = @($office | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'OfficeSettingsStatus' -Default '') -ne 'Read' })
    $gpRead = Test-TPSectionCollected $int 'AdminTemplatePolicies'
    $gp = @(Select-TPAssignedPolicies @(Get-TPObjectField -Item $data -Key 'AdminTemplatePolicies' -Default @()))
    $gpOffice = @($gp | Where-Object { [int](Get-TPObjectField -Item $_ -Key 'OfficeDefinitionCount' -Default 0) -gt 0 })
    $gpUnread = @($gp | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'DefinitionsStatus' -Default '') -ne 'Read' })
    $scope = "$($baseline.Name), $($baseline.Profile) ($($baseline.Subset))"
    $edition = 'Microsoft documents these Office policies as applying to Microsoft 365 Apps for enterprise, not Microsoft 365 Apps for business; which edition the devices run is not read.'
    $outside = 'Settings deployed through the Office cloud policy service or on-premises Group Policy are not visible to this read.'
    $required = "$scope`: all $(@($baseline.Settings).Count) settings set by an assigned Intune policy to the state the benchmark requires"
    $gpNames = (@($gpOffice | ForEach-Object { & $pname $_ }) -join ', ')
    $gpUnreadNames = (@($gpUnread | ForEach-Object { & $pname $_ }) -join ', ')

    if ($read.Count -eq 0) {
        $why = @()
        if ($unread.Count) { $why += "the settings of $($unread.Count) assigned Settings Catalog policy(ies) could not be read in full ($((@($unread | ForEach-Object { & $pname $_ })) -join ', ')), and they may configure Office" }
        if (-not $gpRead) { $why += 'the Administrative Templates policies were not read' }
        if ($gpOffice.Count) { $why += "Office settings are configured only in Administrative Templates policy(ies) ($gpNames), whose values this assessment does not read" }
        if ($gpUnread.Count) { $why += "the settings of Administrative Templates policy(ies) $gpUnreadNames could not be read, and they may configure Office" }
        if ($why.Count) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "Not assessed: no assigned Settings Catalog policy was read that configures Office, and whether Office macros are hardened is not established, because $($why -join '; ')." `
                -CurrentValue 'No Settings Catalog Office policy read' -RequiredValue $required
        } else {
            Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "No assigned Intune policy configures Office macro or active-content settings: no Settings Catalog policy (or Microsoft 365 Apps security baseline) sets an Office setting, and no Administrative Templates policy holds one. Macros in Office files, Excel XLM and DDE, Protected View and trusted locations are left to Office's defaults, which users can change. $outside $edition" `
                -CurrentValue 'No assigned Intune Office policy' -RequiredValue $required -Remediation $ctrl.Remediation
        }
        return
    }

    $maps = @($read | ForEach-Object { [pscustomobject]@{
        DisplayName = (& $pname $_)
        Values = (Get-TPObjectField -Item $_ -Key 'OfficeSettingValues' -Default $null)
        Labels = (Get-TPObjectField -Item $_ -Key 'OfficeSettingLabels' -Default $null) } })
    $rows = @(Get-TPOfficeMacroBaselineRows -Policies $maps -Catalog $baseline)
    $met = @($rows | Where-Object Status -eq 'Met'); $below = @($rows | Where-Object Status -eq 'Below')
    $unset = @($rows | Where-Object Status -eq 'NotSet'); $odd = @($rows | Where-Object Status -eq 'Unrecognized')
    # Settings left unset by the Settings Catalog policies may be set where this read cannot see.
    $blind = ($gpOffice.Count -gt 0 -or $gpUnread.Count -gt 0 -or -not $gpRead -or $unread.Count -gt 0)
    $verified = @(); $short = @(); $unknown = @()
    if ($met.Count) { $verified += "$($met.Count) of $($rows.Count) settings of the $scope are set as required across $($read.Count) assigned Office policy(ies) ($((@($maps.DisplayName)) -join ', ')): $(($met.Cis) -join ', ')." }
    if ($below.Count) {
        $short += 'Set to a state the benchmark does not accept: ' + (($below | ForEach-Object { "$($_.Cis) $($_.App) $($_.Title) ($(@($_.Observed) -join ' / '); requires $($_.Required))" }) -join '; ') + '.'
    }
    $unsetText = ($unset | ForEach-Object { "$($_.Cis) $($_.App) $($_.Title)$(if ($_.NotConfigured) { " (not configured: $($_.NotConfigured))" })" }) -join '; '
    if ($unset.Count -and -not $blind) { $short += "Not set by any assigned Office policy, which the benchmark requires: $unsetText." }
    if ($unset.Count -and $blind) { $unknown += "whether $($unset.Count) setting(s) are set elsewhere: $unsetText." }
    if ($odd.Count) { $unknown += 'a value this assessment does not recognize for ' + (($odd | ForEach-Object { "$($_.Cis) $($_.App) $($_.Title) ($(@($_.Observed) -join ' / '))" }) -join '; ') + '.' }
    if ($unread.Count) { $unknown += "the Office settings of $($unread.Count) assigned Settings Catalog policy(ies) that could not be read in full ($((@($unread | ForEach-Object { & $pname $_ })) -join ', '))." }
    if (-not $gpRead) { $unknown += 'the Administrative Templates policies, which were not read, so an Office setting there that conflicts with the Settings Catalog value is not ruled out.' }
    if ($gpOffice.Count) { $unknown += "the values of $($gpOffice.Count) Administrative Templates policy(ies) that hold Office settings ($gpNames), which this assessment does not read; a value there can conflict with the Settings Catalog value." }
    if ($gpUnread.Count) { $unknown += "the settings of Administrative Templates policy(ies) $gpUnreadNames, which could not be read." }
    if ($verified.Count) { $verified[-1] = "$($verified[-1]) $edition" }
    $affected = @($rows | Where-Object Status -ne 'Met' | ForEach-Object {
        [ordered]@{ Cis = $_.Cis; App = $_.App; Setting = $_.Title; Status = $_.Status; Observed = (@($_.Observed) -join ' / '); Required = $_.Required } })
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -AffectedObjects $affected `
        -CurrentValue "$($met.Count) of $($rows.Count) benchmark settings set as required across $($read.Count) assigned Office policy(ies)" `
        -RequiredValue $required
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
# The five Level 1 Windows Update for Business recommendations of the CIS Microsoft
# Intune for Windows 11 Benchmark v5.0.0 (owner's decision, 2026-10-26), judged on every
# ASSIGNED update ring (Graph windowsUpdateForBusinessConfiguration). Each CIS setting is
# a Policy CSP Update node; the ring property that writes it (Microsoft Learn: Intune
# "Update rings policy settings", the CSP reference each ring setting names):
#   104.1 Allow Auto Update = Enabled, never 5 "Turn off automatic updates"
#         -> automaticUpdateMode (Update/AllowAutoUpdate). The five modes Graph documents
#         map to CSP 0-4 (notifyDownload 0 ... autoInstallAndRebootWithoutEndUserControl
#         4); a ring cannot write 5. userDefined ("no intent") and windowsDefault ("Reset
#         to Windows default") set nothing, which the not-configured rule makes a
#         shortfall: the Windows default (auto install and restart) is named, never credited.
#   104.2 Defer Feature Updates Period in Days >= 180
#         -> featureUpdatesDeferralPeriodInDays (Update/DeferFeatureUpdatesPeriodInDays).
#   104.3 Manage preview builds = 0 "Disable preview builds" (Update/ManagePreviewBuilds).
#         Microsoft's ring settings reference maps the ring's "Enable pre-release builds"
#         to BranchReadinessLevel (businessReadyUpdatesOnly), and one Intune education
#         page maps it to ManagePreviewBuilds: the pages disagree, and no ring property is
#         documented to write Disable. So a ring selecting an Insider channel is a
#         shortfall, and Disable is credited only from an assigned Settings Catalog policy
#         that sets ManagePreviewBuilds to 0 (Intune-EndpointSecurity UpdateSettingsPolicies).
#   104.4 Scheduled Install Day = Every day (CSP 0) -> installationSchedule of type
#         windowsUpdateScheduledInstall with scheduledInstallDay "everyday". Windows applies
#         the day only with AllowAutoUpdate 3 or 4; an active-hours schedule sets no day,
#         which the benchmark audits as not set.
#   104.5 Block "Pause Updates" ability = Block (SetDisablePauseUXAccess = 1)
#         -> userPauseAccess "disabled" (Intune: "Option to pause Windows updates: Disable").
# A Settings Catalog policy that sets one of these nodes to a value the benchmark does
# not accept is a shortfall too, because on the device it is the same CSP value.
# Assignment groups are not resolved: "every assigned ring" is every ring with an assignment.
function Get-TPWufbRingVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Ring)
    $name = [string](Get-TPObjectField -Item $Ring -Key 'DisplayName' -Default '')
    if (-not $name) { $name = [string](Get-TPObjectField -Item $Ring -Key 'Id' -Default 'unnamed ring') }
    $ws = Get-TPObjectField -Item $Ring -Key 'WufbSettings' -Default $null
    $has = {
        param($o, [string] $k)
        if ($o -is [System.Collections.IDictionary]) { return $o.Contains($k) }
        return ($null -ne $o -and $null -ne $o.PSObject.Properties[$k])
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = { param($cis, $title, $state, $text) $rows.Add([pscustomobject]@{ Ring = $name; Cis = $cis; Setting = $title; State = $state; Text = $text }) }
    if ($null -eq $ws) {
        foreach ($c in @(@('104.1', 'Allow Auto Update'), @('104.2', 'Defer Feature Updates Period in Days'), @('104.3', 'Manage preview builds'), @('104.4', 'Scheduled Install Day'), @('104.5', 'Block "Pause Updates" ability'))) {
            & $add $c[0] $c[1] 'NotRead' 'the ring''s settings were not read (a results file from before they were collected)'
        }
        return @($rows)
    }
    # 104.1
    if (-not (& $has $ws 'AutomaticUpdateMode')) { & $add '104.1' 'Allow Auto Update' 'NotRead' 'automaticUpdateMode was not returned' }
    else {
        $v = [string](Get-TPObjectField -Item $ws -Key 'AutomaticUpdateMode' -Default '')
        $labels = @{ notifyDownload = 'Notify download'; autoInstallAtMaintenanceTime = 'Auto install at maintenance time'; autoInstallAndRebootAtMaintenanceTime = 'Auto install and restart at maintenance time'
                     autoInstallAndRebootAtScheduledTime = 'Auto install and restart at a scheduled time'; autoInstallAndRebootWithoutEndUserControl = 'Auto install and restart without end-user control' }
        if ($labels.ContainsKey($v)) { & $add '104.1' 'Allow Auto Update' 'Met' "automatic updates on ($($labels[$v]))" }
        elseif ($v -in @('', 'userDefined', 'windowsDefault')) { & $add '104.1' 'Allow Auto Update' 'Short' "automatic update behavior is not set ($(if ($v) { $v } else { 'empty' })); Windows defaults to auto install and restart, but nothing enforces it" }
        else { & $add '104.1' 'Allow Auto Update' 'Unrecognized' "automaticUpdateMode '$v' is not a value Microsoft documents" }
    }
    # 104.2
    if (-not (& $has $ws 'FeatureUpdatesDeferralPeriodInDays')) { & $add '104.2' 'Defer Feature Updates Period in Days' 'NotRead' 'featureUpdatesDeferralPeriodInDays was not returned' }
    else {
        $raw = Get-TPObjectField -Item $ws -Key 'FeatureUpdatesDeferralPeriodInDays' -Default $null
        $n = 0
        if ($null -eq $raw -or "$raw" -eq '') { & $add '104.2' 'Defer Feature Updates Period in Days' 'Short' 'no feature update deferral is set' }
        elseif ("$raw" -match '^\d+$' -and [int]::TryParse("$raw", [System.Globalization.NumberStyles]::None, [cultureinfo]::InvariantCulture, [ref]$n)) {
            if ($n -ge 180) { & $add '104.2' 'Defer Feature Updates Period in Days' 'Met' "feature updates deferred $n days" }
            else { & $add '104.2' 'Defer Feature Updates Period in Days' 'Short' "feature updates deferred $n days (180 or more required)" }
        } else { & $add '104.2' 'Defer Feature Updates Period in Days' 'Unrecognized' "featureUpdatesDeferralPeriodInDays '$raw' is not a whole number" }
    }
    # 104.3 (the ring's part: a pre-release channel)
    if (-not (& $has $ws 'BusinessReadyUpdatesOnly')) { & $add '104.3' 'Manage preview builds' 'NotRead' 'businessReadyUpdatesOnly was not returned' }
    else {
        $v = [string](Get-TPObjectField -Item $ws -Key 'BusinessReadyUpdatesOnly' -Default '')
        $insider = @{ windowsInsiderBuildFast = 'Dev Channel'; windowsInsiderBuildSlow = 'Beta Channel'; windowsInsiderBuildRelease = 'Release Preview' }
        if ($insider.ContainsKey($v)) { & $add '104.3' 'Manage preview builds' 'Short' "the ring enables pre-release builds ($($insider[$v]))" }
        elseif ($v -in @('', 'userDefined', 'all', 'businessReadyOnly')) { & $add '104.3' 'Manage preview builds' 'NoPrerelease' 'no pre-release channel selected' }
        else { & $add '104.3' 'Manage preview builds' 'Unrecognized' "businessReadyUpdatesOnly '$v' is not a value Microsoft documents" }
    }
    # 104.4
    if (-not (& $has $ws 'InstallationSchedule')) { & $add '104.4' 'Scheduled Install Day' 'NotRead' 'installationSchedule was not returned' }
    else {
        $sch = Get-TPObjectField -Item $ws -Key 'InstallationSchedule' -Default $null
        $type = [string](Get-TPObjectField -Item $sch -Key 'Type' -Default '')
        $day = [string](Get-TPObjectField -Item $sch -Key 'ScheduledInstallDay' -Default '')
        $days = @('sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday')
        if ($null -eq $sch) { & $add '104.4' 'Scheduled Install Day' 'Short' 'no installation schedule is set' }
        elseif ($type -match 'windowsUpdateActiveHoursInstall$') { & $add '104.4' 'Scheduled Install Day' 'Short' 'the ring installs around active hours, so no scheduled install day is set' }
        elseif ($type -match 'windowsUpdateScheduledInstall$') {
            if ($day -eq 'everyday') { & $add '104.4' 'Scheduled Install Day' 'Met' 'scheduled install day is every day' }
            elseif ($day -in $days) { & $add '104.4' 'Scheduled Install Day' 'Short' "scheduled install day is $day (every day required)" }
            elseif ($day -in @('', 'userDefined')) { & $add '104.4' 'Scheduled Install Day' 'Short' 'no scheduled install day is set' }
            else { & $add '104.4' 'Scheduled Install Day' 'Unrecognized' "scheduledInstallDay '$day' is not a value Microsoft documents" }
        } else { & $add '104.4' 'Scheduled Install Day' 'Unrecognized' "installation schedule type '$type' is not one Microsoft documents" }
    }
    # 104.5
    if (-not (& $has $ws 'UserPauseAccess')) { & $add '104.5' 'Block "Pause Updates" ability' 'NotRead' 'userPauseAccess was not returned' }
    else {
        $v = [string](Get-TPObjectField -Item $ws -Key 'UserPauseAccess' -Default '')
        if ($v -eq 'disabled') { & $add '104.5' 'Block "Pause Updates" ability' 'Met' 'users cannot pause updates' }
        elseif ($v -eq 'enabled') { & $add '104.5' 'Block "Pause Updates" ability' 'Short' 'users may pause updates' }
        elseif ($v -in @('', 'notConfigured')) { & $add '104.5' 'Block "Pause Updates" ability' 'Short' 'the option to pause updates is not configured, so users may pause updates (the Windows default)' }
        else { & $add '104.5' 'Block "Pause Updates" ability' 'Unrecognized' "userPauseAccess '$v' is not a value Microsoft documents" }
    }
    return @($rows)
}

# INT-2.5's Settings Catalog half: every value an assigned general Settings Catalog policy
# sets on the five Update nodes. Matched by the CSP node at the end of the setting
# definition id; a choice value ends with "_<CSP value>" and an integer is the number.
function Get-TPWufbCatalogFindings {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Policies)
    $out = [ordered]@{ Short = @(); Unrecognized = @(); DisablePreview = @(); Unread = @() }
    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $name = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '')
        if (-not $name) { $name = [string](Get-TPObjectField -Item $p -Key 'Id' -Default 'unnamed policy') }
        $probe = Get-TPIntunePolicySettingMatches -Policy $p -Pattern '(^|_)update_allowautoupdate$'
        if (-not $probe.Read) { $out.Unread += $name }
        foreach ($node in 'allowautoupdate', 'deferfeatureupdatesperiodindays', 'managepreviewbuilds', 'scheduledinstallday', 'setdisablepauseuxaccess') {
            $m = Get-TPIntunePolicySettingMatches -Policy $p -Pattern "(^|_)update_$node`$"
            foreach ($v in $m.Values) {
                $n = -1
                if ($v -match '(?:^|_)(\d{1,9})$') { $n = [int]$Matches[1] }
                if ($n -lt 0) { $out.Unrecognized += "$name ($node = $v)"; continue }
                switch ($node) {
                    'allowautoupdate'                 { if ($n -eq 5) { $out.Short += "CIS 104.1: $name turns off automatic updates (Allow Auto Update = 5)." } elseif ($n -gt 5) { $out.Unrecognized += "$name (Allow Auto Update = $n)" } }
                    'deferfeatureupdatesperiodindays' { if ($n -lt 180) { $out.Short += "CIS 104.2: $name defers feature updates $n days (180 or more required)." } }
                    'managepreviewbuilds'             { if ($n -eq 0) { $out.DisablePreview += $name } elseif ($n -le 3) { $out.Short += "CIS 104.3: $name sets Manage preview builds to $(@('', 'disable once the next release is public', 'enable preview builds', 'left to user selection')[$n]) (Disable preview builds required)." } else { $out.Unrecognized += "$name (Manage preview builds = $n)" } }
                    'scheduledinstallday'             { if ($n -ge 1 -and $n -le 7) { $out.Short += "CIS 104.4: $name sets Scheduled Install Day to one day of the week (every day required)." } elseif ($n -gt 7) { $out.Unrecognized += "$name (Scheduled Install Day = $n)" } }
                    'setdisablepauseuxaccess'         { if ($n -eq 0) { $out.Short += "CIS 104.5: $name lets users pause updates (Block ""Pause Updates"" ability = 0)." } elseif ($n -gt 1) { $out.Unrecognized += "$name (Block Pause Updates = $n)" } }
                }
            }
        }
    }
    return $out
}

function Test-TPControlIntuneWindowsUpdate {
    [CmdletBinding()] param()
    $cid = 'INT-2.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $int = Get-TPRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Intune compliance data not collected'; return }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $int 'UpdatePolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'UpdatePolicies was not collected; not assessed.'
        return
    }
    $allRings = @(Get-TPObjectField -Item $int.Data -Key 'UpdatePolicies' -Default @() | Where-Object { $null -ne $_ })
    $rings = @(Select-TPAssignedPolicies $allRings)
    $note = if ($allRings.Count -gt $rings.Count) { " $($allRings.Count - $rings.Count) unassigned ring(s) were not counted." } else { '' }
    if ($rings.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No assigned Windows Update for Business ring found in Intune.$note Endpoints may not receive security updates on a managed schedule. Verify via Windows Update rings." -Remediation $ctrl.Remediation
        return
    }
    # One verdict list per ring, kept with the ring (two rings may share a name).
    $perRing = @($rings | ForEach-Object { ,@(Get-TPWufbRingVerdict -Ring $_) })
    $rows = @($perRing | ForEach-Object { $_ })
    # The Settings Catalog half (Manage preview builds, and any catalog value that defeats a ring).
    $es = Get-TPRawData -Key 'Intune-EndpointSecurity'
    $catRead = ($es -and $es.Success -and (Test-TPSectionCollected $es 'UpdateSettingsPolicies'))
    $cat = if ($catRead) { Get-TPWufbCatalogFindings -Policies @(Select-TPAssignedPolicies @(Get-TPObjectField -Item $es.Data -Key 'UpdateSettingsPolicies' -Default @())) } else { $null }

    $verified = @(); $short = @(); $notEst = @(); $affected = @()
    foreach ($ringRows in $perRing) {
        $mine = @($ringRows | Where-Object { $_.Cis -ne '104.3' })
        $name = [string]@($ringRows)[0].Ring
        $met = @($mine | Where-Object State -eq 'Met')
        if ($met.Count) { $verified += "$name meets $(@($met | ForEach-Object { "CIS $($_.Cis) ($($_.Text))" }) -join ', ')." }
        foreach ($x in @($mine | Where-Object State -eq 'Short')) {
            $short += "CIS $($x.Cis) $($x.Setting): in $name $($x.Text)."
            $affected += [ordered]@{ Ring = $name; Cis = $x.Cis; Setting = $x.Setting; Observed = $x.Text }
        }
        foreach ($x in @($mine | Where-Object { $_.State -in @('NotRead', 'Unrecognized') })) { $notEst += "CIS $($x.Cis) $($x.Setting) in ${name}: $($x.Text)." }
    }
    # 104.3, judged across the rings and the Settings Catalog together.
    $pre = @($rows | Where-Object Cis -eq '104.3')
    foreach ($x in @($pre | Where-Object State -eq 'Short')) {
        $short += "CIS 104.3 Manage preview builds: in $($x.Ring) $($x.Text)."
        $affected += [ordered]@{ Ring = $x.Ring; Cis = '104.3'; Setting = $x.Setting; Observed = $x.Text }
    }
    foreach ($x in @($pre | Where-Object { $_.State -in @('NotRead', 'Unrecognized') })) { $notEst += "CIS 104.3 Manage preview builds in $($x.Ring): $($x.Text)." }
    if ($null -ne $cat) {
        $short += @($cat.Short)
        foreach ($u in @($cat.Unrecognized)) { $notEst += "A Settings Catalog Update value is not one Microsoft documents: $u." }
    }
    $ringPreOk = (@($pre | Where-Object State -ne 'NoPrerelease').Count -eq 0)
    $catPreShort = ($null -ne $cat -and @($cat.Short | Where-Object { $_ -like 'CIS 104.3:*' }).Count -gt 0)
    if ($ringPreOk -and -not $catPreShort) {
        if ($null -eq $cat) {
            $notEst += 'CIS 104.3 Manage preview builds: an update ring has no setting Microsoft documents as writing Disable preview builds, and the Settings Catalog policies were not read (not collected in this run or this results file).'
        } elseif (@($cat.Unread).Count) {
            $notEst += "CIS 104.3 Manage preview builds: the settings of $(@($cat.Unread) -join ', ') were not read, so whether one sets Manage preview builds is not established."
        } elseif (@($cat.DisablePreview).Count) {
            $verified += "CIS 104.3 Manage preview builds is Disable preview builds ($(@($cat.DisablePreview | Select-Object -Unique) -join ', ')), and no assigned ring selects a pre-release channel."
        } else {
            $notEst += 'CIS 104.3 Manage preview builds: no assigned ring selects a pre-release channel, but no assigned Settings Catalog policy sets Manage preview builds to Disable preview builds. Microsoft''s pages disagree on whether a ring writes that setting (the ring settings reference maps its pre-release option to BranchReadinessLevel), so Disable is not established.'
        }
    }
    $lead = "$($rings.Count) assigned Windows Update for Business ring(s): $(@($perRing | ForEach-Object { @($_)[0].Ring }) -join ', ').$note"
    if ($verified.Count) { $verified = @($lead) + $verified }
    elseif ($short.Count) { $short[0] = "$lead $($short[0])" }
    elseif ($notEst.Count) { $notEst[0] = "$lead $($notEst[0])" }
    $cur = @($perRing | ForEach-Object {
        "$(@($_)[0].Ring): $(@($_ | Where-Object State -eq 'Met').Count) of 4 ring settings met"
    }) -join '; '
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $notEst `
        -CurrentValue $cur `
        -RequiredValue 'Every assigned update ring: automatic updates on (CIS 104.1), feature updates deferred 180 days or more (104.2), scheduled install day every day (104.4), users blocked from pausing updates (104.5); no ring on a pre-release channel and Manage preview builds = Disable preview builds in an assigned Settings Catalog policy (104.3)' `
        -AffectedObjects $affected
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
    # Judged against Microsoft's App Protection Data Protection Framework, Level 2
    # (enterprise enhanced; it includes every Level 1 setting), conditional launch,
    # owner's decision 2026-10-26. Only the rows whose value Microsoft states and
    # Graph v1.0 returns are judged, on every assigned iOS/iPadOS and Android app
    # protection policy:
    #   Jailbroken/rooted devices: Block access (L1)    deviceComplianceRequired = true
    #     (the portal offers Block access or Wipe data for this row; both meet it)
    #   Min OS version: Block access (L2)               minimumRequiredOsVersion set
    #     (Microsoft gives a format and an N-1 recommendation, not a value, so the
    #     version itself is not judged)
    #   Max PIN attempts: 5 (L1)                         maximumPinRetries 1..5
    #   Offline grace period: 10080 min / Block (L1)     periodOfflineBeforeAccessCheck <= 10080 min
    #   Offline grace period: 30 days / Wipe (L2)        periodOfflineBeforeWipeIsEnforced <= 30 days
    # Every other Level 2 conditional launch row is named as not read. App protection
    # applies to iOS/iPadOS and Android apps; a tenant with neither a mobile policy
    # nor an enrolled mobile device has nothing for this control to govern.
    $all  = @(@(Get-TPObjectField -Item $int.Data -Key 'AppProtectionPolicies' -Default @()) | Where-Object { $null -ne $_ })
    $prot = @(Select-TPAssignedPolicies @($all | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Type' -Default '') -match '(?i)(ios|android)ManagedAppProtection$' }))
    $notRead = 'Level 2 conditional launch rows this check does not read: Disabled account; Min OS version against Microsoft''s N-1 guidance (only that a minimum is set); Android Min patch version, Play Integrity (SafetyNet) attestation and hardware-backed key, Require threat scan on apps, Require device lock, Samsung Knox device attestation.'
    $req = "Every assigned iOS/iPadOS and Android app protection policy: Jailbroken/rooted devices blocked; Min OS version set (Block access); Max PIN attempts 5 or fewer; Offline grace period Block access 10080 minutes or less; Offline grace period Wipe data 30 days or less (Microsoft App Protection Framework, Level 2). $notRead"
    if ($prot.Count -eq 0) {
        $dc = Get-TPRawData -Key 'Intune-DeviceCompliance'
        $mobile = if ($dc -and $dc.Success) { Get-TPEnrolledPlatformCount -Raw $dc -Pattern '^(iOS|iPadOS|Android)' } else { $null }
        if ($mobile -eq 0) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "No assigned iOS/iPadOS or Android app protection policy exists and no iOS, iPadOS or Android device is enrolled in Intune (enrolled: $(Get-TPEnrolledPlatformSummary -Raw $dc)). App protection conditional launch applies to iOS/iPadOS and Android apps, so it governs nothing here. Phones reaching company data without enrolling would not appear in the inventory; INT-1.4 judges app protection coverage."
        } elseif ($null -eq $mobile) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
                -Detail 'No assigned iOS/iPadOS or Android app protection policy exists, and the managed-device inventory was not read, so whether any mobile device is in use is unknown. Not assessed.'
        } else {
            Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
                -Detail "$mobile iOS/iPadOS or Android device(s) are enrolled, but no assigned iOS/iPadOS or Android app protection policy exists, so no conditional launch check applies to corporate apps on them." `
                -CurrentValue 'No assigned iOS/iPadOS or Android app protection policy' -RequiredValue $req -Remediation $ctrl.Remediation
        }
        return
    }
    $nameOf = { param($p) $n = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default ''); if ($n) { $n } else { [string](Get-TPObjectField -Item $p -Key 'Id' -Default 'unnamed policy') } }
    $dur = {
        param($v)
        if ($null -eq $v -or "$v" -eq '') { return $null }
        try { $t = [System.Xml.XmlConvert]::ToTimeSpan([string]$v) } catch { return $null }
        if ($t -le [TimeSpan]::Zero) { return $null }
        $t
    }
    # Each row: a judge returning 'Met', 'Short' or 'Unread' for one policy.
    $rows = @(
        @{ Name = 'Jailbroken/rooted devices blocked'; Judge = {
            param($p) $v = Get-TPObjectField -Item $p -Key 'DeviceComplianceRequired' -Default $null
            if ($null -eq $v) { 'Unread' } elseif ($v -eq $true) { 'Met' } else { 'Short' } } }
        @{ Name = 'Min OS version set (Block access)'; Judge = {
            param($p) if (-not ($p -is [System.Collections.IDictionary] -and $p.Contains('MinimumRequiredOsVersion')) -and $null -eq $p.PSObject.Properties['MinimumRequiredOsVersion']) { return 'Unread' }
            if ([string](Get-TPObjectField -Item $p -Key 'MinimumRequiredOsVersion' -Default '')) { 'Met' } else { 'Short' } } }
        @{ Name = 'Max PIN attempts 5 or fewer'; Judge = {
            param($p) $v = Get-TPObjectField -Item $p -Key 'MaximumPinRetries' -Default $null
            if ($null -eq $v) { 'Unread' } elseif ([int]$v -ge 1 -and [int]$v -le 5) { 'Met' } elseif ([int]$v -le 0) { 'Unread' } else { 'Short' } } }
        @{ Name = 'Offline grace period Block access 10080 minutes or less'; Judge = {
            param($p) $t = & $dur (Get-TPObjectField -Item $p -Key 'PeriodOfflineBeforeAccessCheck' -Default $null)
            if ($null -eq $t) { 'Unread' } elseif ($t.TotalMinutes -le 10080) { 'Met' } else { 'Short' } } }
        @{ Name = 'Offline grace period Wipe data 30 days or less'; Judge = {
            param($p) $t = & $dur (Get-TPObjectField -Item $p -Key 'PeriodOfflineBeforeWipeIsEnforced' -Default $null)
            if ($null -eq $t) { 'Unread' } elseif ($t.TotalDays -le 30) { 'Met' } else { 'Short' } } }
    )
    # A row no policy meets is not configured anywhere: Gap (the not-configured
    # rule). Partial only when every row is met somewhere and some policy falls short.
    $verified = @(); $short = @(); $unread = @(); $noneMet = $false
    foreach ($r in $rows) {
        $s = @(); $u = @()
        foreach ($p in $prot) {
            $v = & $r.Judge $p
            if ($v -eq 'Short') { $s += (& $nameOf $p) } elseif ($v -eq 'Unread') { $u += (& $nameOf $p) }
        }
        if ($s.Count -eq $prot.Count) { $noneMet = $true }
        if ($s.Count) { $short += "$($r.Name): not met by $($s.Count) of $($prot.Count) policy(ies) ($(@($s | Select-Object -First 5) -join ', ')$(if ($s.Count -gt 5) { ", and $($s.Count - 5) more" }))." }
        if ($u.Count) { $unread += "$($r.Name): value not returned or not recognized for $($u.Count) policy(ies) ($(@($u | Select-Object -First 5) -join ', ')$(if ($u.Count -gt 5) { ", and $($u.Count - 5) more" }))." }
        if (-not $s.Count -and -not $u.Count) { $verified += "$($r.Name) in all $($prot.Count) assigned iOS/iPadOS and Android app protection policy(ies)." }
    }
    $cur = if ($short.Count) { "Shortfalls on $($short.Count) of $($rows.Count) Level 2 conditional launch rows" } elseif ($unread.Count) { "$($unread.Count) of $($rows.Count) rows not read" } else { "All $($rows.Count) judged Level 2 conditional launch rows met in $($prot.Count) policy(ies)" }
    $mode = if ($noneMet) { 'Gap' } else { 'Auto' }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unread -CurrentValue $cur -RequiredValue $req -ShortfallState $mode
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

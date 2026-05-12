#
# Test-NRGControlIntune.ps1
# Evaluates Microsoft Intune endpoint management controls.
#
# Controls:
#   ITN-1.1  Intune MDM authority configured
#   ITN-1.2  Windows device compliance policy requires encryption
#   ITN-1.3  Windows device compliance policy requires AV and firewall
#   ITN-1.4  iOS App Protection (MAM) policy configured
#   ITN-1.5  Android App Protection (MAM) policy configured
#   ITN-1.6  Windows Hello for Business policy configured
#   ITN-1.7  Microsoft Defender for Endpoint connector enabled
#   ITN-2.1  Enrollment restrictions configured
#
# Reads: Get-NRGRawData -Key 'Intune'
#
# NIST SP 800-53: CM-2, CM-6, CM-7, SC-28, SI-3
# MITRE ATT&CK:   T1082, T1005, T1078, T1486
#

function Test-NRGControlIntune {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'Intune'

    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'Intune collector did not run.' }
        foreach ($id in @('ITN-1.1','ITN-1.2','ITN-1.3','ITN-1.4','ITN-1.5','ITN-1.6','ITN-1.7','ITN-2.1')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Intune' -Title ($ctrl.Title) -Detail $detail
        }
        return
    }

    $overview      = $raw.Data['ManagedDeviceOverview']
    $compPolicies  = @($raw.Data['CompliancePolicies'])
    $enrollConfigs = @($raw.Data['EnrollmentConfigs'])
    $mtdConnectors = @($raw.Data['MtdConnectors'])
    $mamPolicies   = @($raw.Data['AppProtectionPolicies'])
    $devConfigs    = @($raw.Data['DeviceConfigurations'])

    #--------------------------------------------------------------------------
    # ITN-1.1  Intune MDM authority configured
    # CM-2 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.1'
    if ($overview) {
        $total = $overview.totalCount
        if ($total -gt 0) {
            Add-NRGFinding -ControlId 'ITN-1.1' -State 'Satisfied' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "Intune managing $total device(s). MDM authority: Intune" `
                -RequiredValue 'Intune MDM authority configured with enrolled devices'
        } else {
            Add-NRGFinding -ControlId 'ITN-1.1' -State 'Partial' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'High' `
                -Detail 'Intune is licensed and the API is accessible, but no managed devices found. Endpoint compliance and management policies cannot be enforced until devices are enrolled.' `
                -CurrentValue 'Intune available, 0 managed devices' `
                -RequiredValue 'Devices enrolled and MDM authority active' `
                -Remediation 'Enroll Windows devices via Group Policy, Autopilot, or manual enrollment. Enroll mobile devices via Company Portal app.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.1')
        }
    } else {
        Add-NRGFinding -ControlId 'ITN-1.1' -State 'Gap' `
            -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'Intune device management data not accessible. MDM may not be configured or the tenant does not have an Intune license.' `
            -CurrentValue 'Intune device data not available' `
            -RequiredValue 'Intune MDM authority configured' `
            -Remediation 'Microsoft 365 Business Premium, E3, or standalone Intune license required. Configure MDM authority in Endpoint Manager admin center.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.1')
    }

    #--------------------------------------------------------------------------
    # ITN-1.2  Windows compliance policy requires encryption (BitLocker)
    # SC-28 | T1486, T1005
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.2'
    $winPolicies = @($compPolicies | Where-Object {
        $_.'@odata.type' -match 'Windows' -or $_.platformType -eq 'windows10AndLater'
    })
    if ($winPolicies.Count -gt 0) {
        $encRequired = @($winPolicies | Where-Object {
            $_.bitLockerEnabled -eq $true -or
            $_.storageRequireDeviceEncryption -eq $true -or
            $_.secureBootEnabled -eq $true
        })
        if ($encRequired.Count -gt 0) {
            Add-NRGFinding -ControlId 'ITN-1.2' -State 'Satisfied' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "$($encRequired.Count) Windows compliance policy(ies) require BitLocker/encryption" `
                -RequiredValue 'Windows compliance policy with bitLockerEnabled = true'
        } else {
            Add-NRGFinding -ControlId 'ITN-1.2' -State 'Gap' `
                -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail "Windows compliance policies exist ($($winPolicies.Count)) but none require BitLocker encryption. Devices can be compliant without disk encryption, exposing data if a device is lost or stolen." `
                -CurrentValue 'Windows policy without encryption requirement' `
                -RequiredValue 'Windows compliance policy with BitLocker enabled required' `
                -Remediation 'Endpoint Manager > Devices > Compliance policies > [Windows policy] > Device health > Require BitLocker = Require.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.2')
        }
    } else {
        Add-NRGFinding -ControlId 'ITN-1.2' -State 'Gap' `
            -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No Windows device compliance policies found. Windows endpoints have no enforced security baseline — any device with an M365 account has full access regardless of security posture.' `
            -CurrentValue 'No Windows compliance policies' `
            -RequiredValue 'Windows 10/11 compliance policy requiring BitLocker, AV, and firewall' `
            -Remediation 'Endpoint Manager > Devices > Compliance policies > Create policy (Windows 10 and later). Set BitLocker = Required, AV = Required, Firewall = Required.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.2')
    }

    #--------------------------------------------------------------------------
    # ITN-1.3  Windows compliance policy requires AV and firewall
    # SI-3, SC-7 | T1059
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.3'
    if ($winPolicies.Count -gt 0) {
        $avRequired = @($winPolicies | Where-Object {
            $_.antivirusRequired -eq $true -or
            $_.defenderEnabled -eq $true -or
            $_.realTimeProtectionEnabled -eq $true
        })
        $fwRequired = @($winPolicies | Where-Object {
            $_.firewallEnabled -eq $true -or $_.firewallBlockAllIncomingTraffic -eq $true
        })

        if ($avRequired.Count -gt 0 -and $fwRequired.Count -gt 0) {
            Add-NRGFinding -ControlId 'ITN-1.3' -State 'Satisfied' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "AV required: $($avRequired.Count) policy(ies). Firewall required: $($fwRequired.Count) policy(ies)." `
                -RequiredValue 'Windows compliance policy requiring antivirus and firewall'
        } elseif ($avRequired.Count -gt 0) {
            Add-NRGFinding -ControlId 'ITN-1.3' -State 'Partial' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'High' `
                -Detail 'Antivirus is required by compliance policy but firewall is not. Windows devices can be compliant without an active firewall.' `
                -CurrentValue 'AV required. Firewall not required.' `
                -RequiredValue 'Both antivirus and firewall required' `
                -Remediation 'Endpoint Manager > Compliance policies > [Windows policy] > System security > Firewall = Required.'
        } elseif ($fwRequired.Count -gt 0) {
            Add-NRGFinding -ControlId 'ITN-1.3' -State 'Partial' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'High' `
                -Detail 'Firewall required but antivirus not required by compliance policy. Windows devices can be compliant without active AV protection.' `
                -CurrentValue 'Firewall required. AV not required.' `
                -RequiredValue 'Both antivirus and firewall required' `
                -Remediation 'Endpoint Manager > Compliance policies > [Windows policy] > System security > Antivirus = Required.'
        } else {
            Add-NRGFinding -ControlId 'ITN-1.3' -State 'Gap' `
                -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'No Windows compliance policy requires antivirus or firewall. Endpoints can be enrolled as "compliant" with no AV or firewall active.' `
                -CurrentValue 'AV and firewall not required' `
                -RequiredValue 'Antivirus = Required, Firewall = Required in Windows compliance policy' `
                -Remediation 'Endpoint Manager > Devices > Compliance policies > [Windows policy] > System security: Set Firewall = Required, Antivirus = Required, Real-time protection = Required.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.3')
        }
    } else {
        Add-NRGFinding -ControlId 'ITN-1.3' -State 'NotApplicable' `
            -Category 'Intune' -Title $ctrl.Title `
            -Detail 'No Windows compliance policies — see ITN-1.2.'
    }

    #--------------------------------------------------------------------------
    # ITN-1.4  iOS App Protection (MAM) policy configured
    # CM-7, SC-4 | T1005
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.4'
    $iosPolicies = @($mamPolicies | Where-Object {
        $_.'@odata.type' -match '[Ii]os' -or $_.platform -eq 'iOS'
    })
    if ($iosPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId 'ITN-1.4' -State 'Satisfied' `
            -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($iosPolicies.Count) iOS App Protection policy(ies) configured" `
            -RequiredValue 'iOS MAM policy protecting corporate apps (Outlook, Teams, etc.)'
    } else {
        Add-NRGFinding -ControlId 'ITN-1.4' -State 'Gap' `
            -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No iOS App Protection policy configured. Corporate data accessed via Outlook, Teams, or OneDrive on personal iOS devices has no copy/paste, screenshot, or backup restrictions. If a device is lost or an employee leaves, data cannot be remotely wiped.' `
            -CurrentValue 'No iOS MAM policy' `
            -RequiredValue 'iOS App Protection policy covering Outlook, Teams, OneDrive at minimum' `
            -Remediation 'Endpoint Manager > Apps > App protection policies > Create policy (iOS/iPadOS). Target Outlook, Teams, OneDrive. Set PIN, copy/paste restrictions, and remote wipe capability.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.4')
    }

    #--------------------------------------------------------------------------
    # ITN-1.5  Android App Protection (MAM) policy configured
    # CM-7, SC-4 | T1005
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.5'
    $androidPolicies = @($mamPolicies | Where-Object {
        $_.'@odata.type' -match '[Aa]ndroid' -or $_.platform -eq 'Android'
    })
    if ($androidPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId 'ITN-1.5' -State 'Satisfied' `
            -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($androidPolicies.Count) Android App Protection policy(ies) configured" `
            -RequiredValue 'Android MAM policy protecting corporate apps'
    } else {
        Add-NRGFinding -ControlId 'ITN-1.5' -State 'Gap' `
            -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No Android App Protection policy configured. Corporate data on Android personal devices has no controls. Data can be copied to personal apps, screenshots can be taken, and data cannot be remotely wiped.' `
            -CurrentValue 'No Android MAM policy' `
            -RequiredValue 'Android App Protection policy covering Outlook, Teams, OneDrive at minimum' `
            -Remediation 'Endpoint Manager > Apps > App protection policies > Create policy (Android). Target Outlook, Teams, OneDrive. Set PIN, copy/paste, screenshot restrictions.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.5')
    }

    #--------------------------------------------------------------------------
    # ITN-1.6  Windows Hello for Business policy configured
    # IA-2(8) | T1078, T1621
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.6'
    # Look in enrollment configurations for Windows Hello for Business
    $whfbEnroll = @($enrollConfigs | Where-Object {
        $_.'@odata.type' -match 'WindowsHello' -or $_.displayName -match 'Hello'
    })
    $whfbDevCfg = @($devConfigs | Where-Object {
        $_.'@odata.type' -match 'WindowsIdentityProtection' -or
        $_.'@odata.type' -match 'WindowsHello' -or
        $_.displayName -match 'Hello'
    })
    if ($whfbEnroll.Count -gt 0 -or $whfbDevCfg.Count -gt 0) {
        $total = $whfbEnroll.Count + $whfbDevCfg.Count
        Add-NRGFinding -ControlId 'ITN-1.6' -State 'Satisfied' `
            -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$total Windows Hello for Business policy(ies) configured" `
            -RequiredValue 'Windows Hello for Business enrollment/configuration policy'
    } else {
        Add-NRGFinding -ControlId 'ITN-1.6' -State 'Gap' `
            -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No Windows Hello for Business policy found. Windows sign-in defaults to password only on enrolled devices. WHfB provides phishing-resistant biometric/PIN authentication at the device level.' `
            -CurrentValue 'No WHfB policy' `
            -RequiredValue 'Windows Hello for Business enrollment policy enabled in Intune' `
            -Remediation 'Endpoint Manager > Devices > Enrollment > Windows Hello for Business. Enable and require PIN with biometric option. Or create Identity Protection profile under Device configuration.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.6')
    }

    #--------------------------------------------------------------------------
    # ITN-1.7  Microsoft Defender for Endpoint connector enabled
    # SI-3, SI-4 | T1082, T1059
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-1.7'
    $mdeConnector = @($mtdConnectors | Where-Object {
        $_.partnerUniqueName -match 'Microsoft' -or
        $_.partnerUniqueName -match 'Defender' -or
        $_.partnerUniqueName -match 'AtpConnector'
    })
    if ($mdeConnector.Count -gt 0) {
        $enabled = @($mdeConnector | Where-Object { $_.androidEnabled -eq $true -or $_.iosEnabled -eq $true -or $_.windowsEnabled -eq $true })
        if ($enabled.Count -gt 0) {
            Add-NRGFinding -ControlId 'ITN-1.7' -State 'Satisfied' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'MDE connector enabled and active' `
                -RequiredValue 'MDE-Intune connector enabled with platform coverage'
        } else {
            Add-NRGFinding -ControlId 'ITN-1.7' -State 'Partial' `
                -Category 'Intune' -Title $ctrl.Title -Severity 'High' `
                -Detail 'MDE connector exists in Intune but is not enabled for any platform. Defender risk signals are not feeding into Intune compliance evaluation.' `
                -CurrentValue 'MDE connector present but platform coverage disabled' `
                -RequiredValue 'MDE connector enabled for Windows, iOS, and Android' `
                -Remediation 'Endpoint Manager > Endpoint security > Microsoft Defender for Endpoint > Enable connector. Enable for Windows, iOS, Android as appropriate.'
        }
    } else {
        Add-NRGFinding -ControlId 'ITN-1.7' -State 'Gap' `
            -Category 'Intune' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No Microsoft Defender for Endpoint connector found in Intune. MDE threat risk scores are not integrated with device compliance, meaning compromised devices remain "compliant" in Intune.' `
            -CurrentValue 'No MDE-Intune connector' `
            -RequiredValue 'MDE connector configured and enabled in Intune' `
            -Remediation 'Requires Microsoft Defender for Endpoint (P1 or P2) and Intune. Endpoint Manager > Endpoint security > Microsoft Defender for Endpoint > Open MDE portal and enable Intune connection.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-1.7')
    }

    #--------------------------------------------------------------------------
    # ITN-2.1  Enrollment restrictions configured
    # CM-7, AC-3 | T1078
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'ITN-2.1'
    # Default enrollment restriction allows all platforms — check if custom restrictions exist
    $customRestrictions = @($enrollConfigs | Where-Object {
        $_.'@odata.type' -match 'DeviceEnrollmentPlatformRestriction' -and
        $_.displayName -ne 'All users and all devices'  -and
        $_.priority -ne 0
    })

    if ($customRestrictions.Count -gt 0) {
        Add-NRGFinding -ControlId 'ITN-2.1' -State 'Satisfied' `
            -Category 'Intune' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($customRestrictions.Count) custom enrollment restriction(s) configured" `
            -RequiredValue 'Custom enrollment restrictions beyond the default allow-all policy'
    } else {
        Add-NRGFinding -ControlId 'ITN-2.1' -State 'Partial' `
            -Category 'Intune' -Title $ctrl.Title -Severity 'Medium' `
            -Detail 'No custom enrollment restrictions found. The default policy allows all device types (Android, iOS, Windows, macOS) to enroll without restriction. Personal/unmanaged devices can enroll without controls.' `
            -CurrentValue 'Default enrollment restrictions only (allow all platforms)' `
            -RequiredValue 'Enrollment restrictions limiting allowed platforms and requiring corporate ownership' `
            -Remediation 'Endpoint Manager > Devices > Enrollment restrictions > Create restriction. Block platforms not used in your org. Consider requiring corporate-owned device type.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'ITN-2.1')
    }
}

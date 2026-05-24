#Requires -Version 7.0
#
# Test-NRGControlIntune.ps1
# Evaluates Intune controls. Reads from the three split raw-data keys produced by
# Invoke-NRGCollectIntuneEndpointSecurity / DeviceCompliance / AppProtection.
#
# Controls:
#   ITN-1.1  Device compliance policy active
#   ITN-1.2  Configuration profiles deployed
#   ITN-1.3  App protection (MAM) policies configured
#   ITN-1.4  Enrolled device compliance ratio
#   ITN-1.5  Enrollment restriction policy configured
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

    # Merge fields the legacy ITN-1.x checks expect into a single $d view
    $d = @{
        CompliancePolicies       = if ($dc  -and $dc.Success)  { $dc.Data.CompliancePolicies }       else { @() }
        ConfigurationProfiles    = if ($dc  -and $dc.Success)  { $dc.Data.ConfigurationProfiles }    else { @() }
        AppProtectionPolicies    = if ($app -and $app.Success) { $app.Data.AppProtectionPolicies }   else { @() }
        EnrollmentConfig         = if ($dc  -and $dc.Success)  { $dc.Data.EnrollmentConfig }         else { @() }
        EndpointSecurityPolicies = if ($es  -and $es.Success)  { $es.Data.EndpointSecurityPolicies } else { @() }
    }

    # ITN-1.1 — Device compliance policy active
    $c = Get-NRGControlById -ControlId 'INT-1.1'
    if ($c) {
        $count = @($d.CompliancePolicies).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.1' -State 'Satisfied' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count compliance policies active" `
                -RequiredValue 'At least one compliance policy active'
        } else {
            Add-NRGFinding -ControlId 'INT-1.1' -State 'Gap' `
                -Category 'Endpoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'No device compliance policies configured. Devices without compliance policies are treated as compliant by default.' `
                -CurrentValue 'No compliance policies' `
                -RequiredValue 'At least one compliance policy active' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'INT-1.1')
        }
    }

    # ITN-1.2 — Configuration profiles deployed
    $c = Get-NRGControlById -ControlId 'INT-1.2'
    if ($c) {
        $count = @($d.ConfigurationProfiles).Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.2' -State 'Satisfied' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Informational' `
                -CurrentValue "$count configuration profiles deployed"
        } else {
            Add-NRGFinding -ControlId 'INT-1.2' -State 'Partial' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Medium' `
                -Detail 'No device configuration profiles deployed. Devices are not receiving baseline security configuration.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'INT-1.2')
        }
    }

    # INT-1.3 — BitLocker encryption required on Windows compliance policy
    $c = Get-NRGControlById -ControlId 'INT-1.3'
    if ($c) {
        # Check if any Windows compliance policy requires BitLocker
        $winPolicies = @($d.CompliancePolicies | Where-Object { $_.Platform -match 'Windows|Win10' })
        $bitlockerRequired = $winPolicies | Where-Object { $_.BitLockerEnabled -eq $true }
        if ($winPolicies.Count -eq 0) {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'NotApplicable' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Informational' `
                -Detail 'No Windows compliance policies configured.'
        } elseif ($bitlockerRequired.Count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'Satisfied' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Informational' `
                -Detail "BitLocker required by $($bitlockerRequired.Count) Windows compliance policy(ies)."
        } else {
            Add-NRGFinding -ControlId 'INT-1.3' -State 'Gap' `
                -Category 'Endpoint' -Title $c.Title -Severity $c.Severity `
                -Detail "Windows compliance policy exists but BitLocker encryption is not required. Unencrypted devices can access corporate data." `
                -CurrentValue "BitLocker not required in $($winPolicies.Count) Windows policy(ies)" `
                -RequiredValue 'BitLocker = Require in Windows compliance policy' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'INT-1.3')
        }
    }

    # INT-1.4 — Mobile Application Management (MAM) app protection policies
    $c = Get-NRGControlById -ControlId 'INT-1.4'
    if ($c) {
        $mamPolicies = @($d.AppProtectionPolicies)
        $count = $mamPolicies.Count
        if ($count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.4' -State 'Satisfied' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Informational' `
                -Detail "$count app protection (MAM) policy(ies) configured." `
                -CurrentValue "$count MAM policies active"
        } else {
            Add-NRGFinding -ControlId 'INT-1.4' -State 'Gap' `
                -Category 'Endpoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'No app protection (MAM) policies configured. Corporate data in Office apps on personal devices is unprotected — users can copy/paste or save to personal storage.' `
                -CurrentValue 'No MAM policies' `
                -RequiredValue 'App protection policies for iOS and Android targeting Office apps' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'INT-1.4')
        }
    }
    # INT-1.5 — Antivirus policy deployed via Intune
    $c = Get-NRGControlById -ControlId 'INT-1.5'
    if ($c) {
        # Check endpoint security AV policies; fall back to enrollment config as proxy
        $avPolicies = @($d.EndpointSecurityPolicies | Where-Object { $_.TemplateType -match 'Antivirus|MicrosoftDefender' })
        $enrollConfig = @($d.EnrollmentConfig)
        if ($avPolicies.Count -gt 0) {
            Add-NRGFinding -ControlId 'INT-1.5' -State 'Satisfied' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Informational' `
                -Detail "$($avPolicies.Count) Intune antivirus policy(ies) deployed." `
                -CurrentValue "$($avPolicies.Count) AV policies active"
        } elseif ($enrollConfig.Count -gt 0) {
            # Endpoint security policies not collected — enrollment config present, partial evidence
            Add-NRGFinding -ControlId 'INT-1.5' -State 'Partial' `
                -Category 'Endpoint' -Title $c.Title -Severity 'Medium' `
                -Detail 'Intune endpoint security AV policy data not collected. Verify antivirus policy deployment in Intune > Endpoint security > Antivirus.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'INT-1.5')
        } else {
            Add-NRGFinding -ControlId 'INT-1.5' -State 'Gap' `
                -Category 'Endpoint' -Title $c.Title -Severity $c.Severity `
                -Detail 'No Intune antivirus policies found. Devices may not have a managed AV configuration baseline.' `
                -Remediation $c.Remediation `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'INT-1.5')
        }
    }
}

# ── INT-2.1 Endpoint Detection and Response Deployed ─────────────────────────
function Test-NRGControlIntuneEDR {
    [CmdletBinding()] param()
    $cid = 'INT-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    $edrPolicies = @($int.Data.EndpointDetectionPolicies ?? @())
    if ($edrPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($edrPolicies.Count) EDR/MDE onboarding policy(ies) deployed via Intune."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No EDR onboarding policy found in Intune. Endpoints may not be reporting to Defender for Endpoint.' -Remediation $ctrl.Remediation
    }
}

# ── INT-2.2 Attack Surface Reduction Rules Enabled ───────────────────────────
function Test-NRGControlIntuneASR {
    [CmdletBinding()] param()
    $cid = 'INT-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    $asrPolicies = @($int.Data.ASRPolicies ?? @())
    if ($asrPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($asrPolicies.Count) ASR rule policy(ies) deployed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Attack Surface Reduction rule policies found in Intune. ASR rules block commodity malware delivery vectors including Office macro abuse and credential theft.' -Remediation $ctrl.Remediation
    }
}

# ── INT-2.3 Firewall Policy Deployed via Intune ───────────────────────────────
function Test-NRGControlIntuneFirewall {
    [CmdletBinding()] param()
    $cid = 'INT-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune endpoint security data not collected'; return }
    $fwPolicies = @($int.Data.FirewallPolicies ?? @())
    if ($fwPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($fwPolicies.Count) firewall policy(ies) deployed via Intune."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Windows Firewall policy deployed via Intune. Endpoint firewall configuration is unmanaged.' -Remediation $ctrl.Remediation
    }
}

# ── INT-2.4 Disk Encryption Compliance for macOS ─────────────────────────────
function Test-NRGControlIntuneMacEncryption {
    [CmdletBinding()] param()
    $cid = 'INT-2.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune compliance data not collected'; return }
    $macPolicies = @($int.Data.CompliancePolicies | Where-Object { $_.Platform -match 'macOS|Mac' })
    if ($macPolicies.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No macOS compliance policies found — may not have managed macOS devices'
        return
    }
    $encRequired = @($macPolicies | Where-Object { $_.SystemIntegrityProtectionEnabled -or $_.StorageRequireEncryption }).Count -gt 0
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
    $winUpdatePolicies = @($int.Data.UpdatePolicies ?? @())
    if ($winUpdatePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($winUpdatePolicies.Count) Windows Update compliance policy(ies) deployed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'No Windows Update for Business policy found in Intune. Endpoints may not receive security updates on a managed schedule. Verify via Windows Update rings.' -Remediation $ctrl.Remediation
    }
}

# ── INT-3.1 Device Enrollment Restrictions Configured ────────────────────────
function Test-NRGControlIntuneEnrollmentRestrictions {
    [CmdletBinding()] param()
    $cid = 'INT-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Intune data not collected'; return
    }
    $restrictions = @($int.Data.EnrollmentRestrictions ?? @())
    if ($restrictions.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($restrictions.Count) device enrollment restriction policy(ies) configured."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail 'No custom enrollment restriction policies found. Default allows all platforms and personal devices to enroll without restrictions.' `
            -Remediation $ctrl.Remediation
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
    $appConfig = @($int.Data.AppConfigPolicies ?? @())
    if ($appConfig.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($appConfig.Count) app configuration policy(ies) deployed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
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
    if (-not $int -or -not $int.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Intune app protection data not collected'; return
    }
    $appPolicies = @($int.Data.AppProtectionPolicies ?? @())
    $withLaunch  = @($appPolicies | Where-Object { @($_.ConditionalLaunchSettings ?? @()).Count -gt 0 })
    if ($withLaunch.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($withLaunch.Count) app protection policy(ies) include conditional launch rules."
    } elseif ($appPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail 'App protection policies exist but no conditional launch settings configured. Add: Min OS version, Jailbreak/root detection, Max PIN attempts.' `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No app protection policies with conditional launch configured. Jailbroken devices and outdated OS versions access corporate apps unchecked.' `
            -Remediation $ctrl.Remediation
    }
}

# ── INT-4.1 Windows LAPS Configured ──────────────────────────────────────────
function Test-NRGControlIntuneWindowsLAPS {
    [CmdletBinding()] param()
    $cid = 'INT-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-EndpointSecurity'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune data not collected'; return }
    $lapsPolicies = @($int.Data.LAPSPolicies ?? @())
    if ($lapsPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($lapsPolicies.Count) Windows LAPS policy(ies) deployed. Local administrator passwords are unique, rotated, and escrowed in Entra ID."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Windows LAPS (Local Administrator Password Solution) policy deployed. If any endpoint shares the same local admin password, lateral movement after one compromise exposes all endpoints.' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.2 Windows Hello for Business Deployed ───────────────────────────────
function Test-NRGControlIntuneWindowsHello {
    [CmdletBinding()] param()
    $cid = 'INT-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune data not collected'; return }
    $helloPolicies = @($int.Data.WindowsHelloPolicies ?? @())
    if ($helloPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($helloPolicies.Count) Windows Hello for Business policy(ies) deployed. Phishing-resistant passwordless authentication on enrolled endpoints."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail 'No Windows Hello for Business policy deployed via Intune. WHfB provides phishing-resistant passwordless authentication for all Windows endpoints at no additional license cost.' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.3 Update Compliance / Windows Update for Business Reports ───────────
function Test-NRGControlIntuneUpdateCompliance {
    [CmdletBinding()] param()
    $cid = 'INT-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune data not collected'; return }
    $osCompliant = if ($int.Data.OSComplianceSummary) {
        [int]($int.Data.OSComplianceSummary.CompliantCount ?? 0)
    } else { -1 }
    $totalDevices = if ($int.Data.OSComplianceSummary) {
        [int]($int.Data.OSComplianceSummary.TotalCount ?? 0)
    } else { -1 }
    if ($osCompliant -ge 0 -and $totalDevices -gt 0) {
        $pct = [int]($osCompliant * 100 / $totalDevices)
        if ($pct -ge 90) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$pct% of enrolled devices are OS-version compliant ($osCompliant/$totalDevices)."
        } else {
            Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$pct% OS compliance — $($totalDevices - $osCompliant) device(s) running non-compliant OS versions. Unpatched devices remain vulnerable to known exploits." -CurrentValue "$pct% compliant" -RequiredValue '≥90% compliant' -Remediation $ctrl.Remediation
        }
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Device OS compliance summary not available. Verify device compliance reporting is configured in Intune.' -Remediation $ctrl.Remediation
    }
}

# ── INT-4.4 Mobile Device Compliance Policy Requires PIN/Biometric ────────────
function Test-NRGControlIntuneMobilePIN {
    [CmdletBinding()] param()
    $cid = 'INT-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $int = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if (-not $int -or -not $int.Success) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Intune data not collected'; return }
    $mobilePolicies = @($int.Data.CompliancePolicies | Where-Object { $_.Platform -match 'iOS|Android' })
    if ($mobilePolicies.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No iOS or Android compliance policies — may not have managed mobile devices'; return
    }
    $pinRequired = @($mobilePolicies | Where-Object { $_.PasswordRequired -eq $true -or $_.RequirePassword -eq $true }).Count -gt 0
    if ($pinRequired) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Mobile device compliance policy requires PIN or biometric authentication.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Mobile compliance policies do not require PIN or biometric. Lost or stolen unprotected devices expose all corporate data in managed apps.' -Remediation $ctrl.Remediation
    }
}
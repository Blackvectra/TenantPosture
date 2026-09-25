#Requires -Version 5.1
<#
.SYNOPSIS
    NRG device compliance collector. Runs ON an endpoint, reads local security
    state, writes a JSON result. Read-only.

.DESCRIPTION
    Deployed by RMM (ConnectWise script task, Intune platform script, or a
    scheduled task) and run as SYSTEM. It reads local configuration and writes a
    single JSON file for the RMM to collect. The assessment workstation then
    ingests a folder of those files with:

        .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client.com `
            -DeviceResults .\collected\clientname\

    DELIBERATELY STANDALONE. It does not import NRG-Assessment.psm1, does not
    reach the network, and holds no credentials. It has to run on a bare machine
    with nothing installed, so it can depend on nothing.

    WINDOWS POWERSHELL 5.1. Stock Windows ships 5.1, not 7. The rest of the tool
    requires 7; this file cannot. That means no null-coalescing (??), no
    ternaries, and no PS7-only cmdlets anywhere in this file — a 7-only
    construct here fails on the exact machines it is meant to run on.
    Testing/NRG.DeviceCompliance.Tests.ps1 enforces that statically.

    ELEVATION HONESTY. BitLocker, TPM, Secure Boot and the audit policy cannot
    be read without administrative rights. Run non-elevated, those cmdlets
    return nothing — which is indistinguishable from "not configured" unless the
    script says so. Every such check reports NotAssessed, never Pass and never
    Fail, and the result file records Elevated:false so the ingesting side can
    label the whole run as partial. Reading a silent failure as compliance is
    the bug class this tool exists to avoid.

.PARAMETER OutputPath
    Where to write the JSON. Defaults to
    C:\ProgramData\NRG\device-compliance.json.

.PARAMETER PassThru
    Also emit the result object to the pipeline, for interactive use.

.PARAMETER MaxSignatureAgeDays
    Antivirus definitions older than this fail DEV-2.3. Default 7.

.PARAMETER MaxPatchAgeDays
    No update installed within this window fails DEV-5.2. Default 45.

.PARAMETER MaxInactivitySeconds
    Machine inactivity lock limit above this fails DEV-6.1. Default 900 (15 min).

.EXAMPLE
    .\Invoke-NRGDeviceCompliance.ps1
    Writes C:\ProgramData\NRG\device-compliance.json.

.EXAMPLE
    .\Invoke-NRGDeviceCompliance.ps1 -OutputPath D:\collect\%COMPUTERNAME%.json

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Read-only: reads local state only. Writes exactly one file, the result JSON.
    Exit codes: 0 all assessed checks passed, 2 one or more failed,
                3 ran without elevation (results partial), 4 fatal error.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $OutputPath,

    [Parameter(Mandatory = $false)]
    [switch] $PassThru,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int] $MaxSignatureAgeDays = 7,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int] $MaxPatchAgeDays = 45,

    [Parameter(Mandatory = $false)]
    [ValidateRange(60, 86400)]
    [int] $MaxInactivitySeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptVersion = '1.0.0'
$script:Schema        = 'nrg-device-compliance/1.0'
$script:Checks        = New-Object System.Collections.ArrayList

# ── Result vocabulary ────────────────────────────────────────────────────────
#   Pass          the check ran and the device meets the requirement
#   Fail          the check ran and the device does not
#   NotApplicable the requirement genuinely does not apply (no fixed data
#                 volumes, RDP not enabled, and so on)
#   NotAssessed   the check could NOT run — no elevation, cmdlet absent, feature
#                 not installed. Never treat as either a pass or a failure.
#   Error         the check threw. Same handling as NotAssessed, but it means a
#                 defect in this script rather than a limitation of the host.
#   Info          inventory, not a verdict: the check records what is there
#                 (local administrators, OS build) for a person to review.
#                 Never a pass — reporting these as Pass handed every device a
#                 clean result for a check that judged nothing.

function Add-Check {
    param(
        [Parameter(Mandatory = $true)]  [string] $Id,
        [Parameter(Mandatory = $true)]  [ValidateSet('Pass','Fail','NotApplicable','NotAssessed','Error','Info')] [string] $Result,
        [Parameter(Mandatory = $false)] [string] $Observed = '',
        [Parameter(Mandatory = $false)] [string] $Expected = '',
        [Parameter(Mandatory = $false)] [string] $Detail   = ''
    )
    $null = $script:Checks.Add([PSCustomObject]@{
        Id       = $Id
        Result   = $Result
        Observed = $Observed
        Expected = $Expected
        Detail   = $Detail
    })
}

function Test-Elevated {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-RegValue {
    <#
        Registry read that returns $null rather than throwing when the key or
        value is absent. Absence is a normal, meaningful state here — "the
        policy was never set" — and must not abort the run.
    #>
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Invoke-Check {
    <#
        Runs one check body inside its own try/catch. A single broken check must
        never take the other thirty-four with it — a run that dies halfway
        produces a partial file that looks like a complete one.
    #>
    param(
        [Parameter(Mandatory = $true)] [string] $Id,
        [Parameter(Mandatory = $true)] [scriptblock] $Body,
        [Parameter(Mandatory = $false)] [switch] $NeedsElevation
    )
    if ($NeedsElevation -and -not $script:IsElevated) {
        Add-Check -Id $Id -Result 'NotAssessed' `
            -Detail 'Requires administrative rights. Re-run as SYSTEM or an administrator.'
        return
    }
    try {
        & $Body
    } catch {
        Add-Check -Id $Id -Result 'Error' -Detail $_.Exception.Message
    }
}

$script:IsElevated = Test-Elevated

try {
    # ── Device identity ──────────────────────────────────────────────────────
    $device = [ordered]@{
        Hostname     = $env:COMPUTERNAME
        Domain       = ''
        OSCaption    = ''
        OSVersion    = ''
        OSBuild      = ''
        Manufacturer = ''
        Model        = ''
        Serial       = ''
        LastBootUtc  = ''
        JoinType     = 'Unknown'
    }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $device.OSCaption   = [string]$os.Caption
        $device.OSVersion   = [string]$os.Version
        $device.OSBuild     = [string]$os.BuildNumber
        $device.LastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    } catch { }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $device.Manufacturer = [string]$cs.Manufacturer
        $device.Model        = [string]$cs.Model
        $device.Domain       = [string]$cs.Domain
        if ($cs.PartOfDomain) { $device.JoinType = 'DomainJoined' } else { $device.JoinType = 'Workgroup' }
    } catch { }
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $device.Serial = [string]$bios.SerialNumber
    } catch { }
    # Entra join state, best effort. dsregcmd is present on Win10+.
    try {
        $dsreg = & dsregcmd.exe /status 2>$null
        if ($dsreg) {
            $joined = ($dsreg | Select-String -SimpleMatch 'AzureAdJoined : YES')
            $hybrid = ($dsreg | Select-String -SimpleMatch 'DomainJoined : YES')
            if ($joined -and $hybrid)      { $device.JoinType = 'HybridJoined' }
            elseif ($joined)               { $device.JoinType = 'EntraJoined' }
        }
    } catch { }

    # ═════════════════════════════════════════════════════════════════════════
    # 1. Encryption and boot integrity
    # ═════════════════════════════════════════════════════════════════════════

    Invoke-Check -Id 'DEV-1.1' -NeedsElevation -Body {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-1.1' -Result 'NotAssessed' -Detail 'BitLocker cmdlets unavailable (Home edition or feature absent).'
            return
        }
        $sysDrive = $env:SystemDrive
        $vol = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction Stop
        $status = [string]$vol.ProtectionStatus
        Add-Check -Id 'DEV-1.1' -Result $(if ($status -eq 'On') { 'Pass' } else { 'Fail' }) `
            -Observed "$sysDrive protection $status, $([string]$vol.VolumeStatus)" `
            -Expected 'ProtectionStatus On' `
            -Detail "Encryption method: $([string]$vol.EncryptionMethod); $([string]$vol.EncryptionPercentage)% encrypted."
    }

    Invoke-Check -Id 'DEV-1.2' -NeedsElevation -Body {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-1.2' -Result 'NotAssessed' -Detail 'BitLocker cmdlets unavailable.'
            return
        }
        $fixed = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq 'Data' -and $_.MountPoint -ne $env:SystemDrive })
        if ($fixed.Count -eq 0) {
            Add-Check -Id 'DEV-1.2' -Result 'NotApplicable' -Detail 'No fixed data volumes present.'
            return
        }
        $unprotected = @($fixed | Where-Object { [string]$_.ProtectionStatus -ne 'On' })
        if ($unprotected.Count -eq 0) {
            Add-Check -Id 'DEV-1.2' -Result 'Pass' -Observed "$($fixed.Count) fixed data volume(s), all protected"
        } else {
            Add-Check -Id 'DEV-1.2' -Result 'Fail' `
                -Observed "$($unprotected.Count) of $($fixed.Count) unprotected: $(($unprotected | ForEach-Object { [string]$_.MountPoint }) -join ', ')" `
                -Expected 'All fixed data volumes protected'
        }
    }

    Invoke-Check -Id 'DEV-1.3' -NeedsElevation -Body {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-1.3' -Result 'NotAssessed' -Detail 'BitLocker cmdlets unavailable.'
            return
        }
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ([string]$vol.ProtectionStatus -ne 'On') {
            Add-Check -Id 'DEV-1.3' -Result 'NotApplicable' -Detail 'OS volume is not protected, so there is no key to escrow (see DEV-1.1).'
            return
        }
        $types = @($vol.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
        $hasRecovery = ($types -contains 'RecoveryPassword')
        Add-Check -Id 'DEV-1.3' -Result $(if ($hasRecovery) { 'Pass' } else { 'Fail' }) `
            -Observed "Protectors: $($types -join ', ')" `
            -Expected 'A RecoveryPassword protector exists' `
            -Detail 'This confirms a recovery password EXISTS on the volume. Whether it reached Entra ID or AD is a tenant-side check, not a device-side one.'
    }

    Invoke-Check -Id 'DEV-1.4' -NeedsElevation -Body {
        if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-1.4' -Result 'NotAssessed' -Detail 'Get-Tpm unavailable on this OS edition.'
            return
        }
        $tpm = Get-Tpm -ErrorAction Stop
        $ok = ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled)
        Add-Check -Id 'DEV-1.4' -Result $(if ($ok) { 'Pass' } else { 'Fail' }) `
            -Observed "Present=$($tpm.TpmPresent) Ready=$($tpm.TpmReady) Enabled=$($tpm.TpmEnabled)" `
            -Expected 'TPM present, enabled and ready'
    }

    Invoke-Check -Id 'DEV-1.5' -NeedsElevation -Body {
        if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-1.5' -Result 'NotAssessed' -Detail 'Confirm-SecureBootUEFI unavailable.'
            return
        }
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            Add-Check -Id 'DEV-1.5' -Result $(if ($sb) { 'Pass' } else { 'Fail' }) `
                -Observed "SecureBoot enabled: $sb" -Expected 'Enabled'
        } catch {
            # The cmdlet throws on legacy BIOS rather than returning false.
            Add-Check -Id 'DEV-1.5' -Result 'Fail' `
                -Observed 'Legacy BIOS / non-UEFI boot' -Expected 'UEFI with Secure Boot enabled' `
                -Detail 'Secure Boot cannot be enabled on a legacy BIOS install. This needs a firmware change and, usually, a rebuild.'
        }
    }

    Invoke-Check -Id 'DEV-1.6' -Body {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $running = @($dg.SecurityServicesRunning)
        # 1 = Credential Guard, 2 = HVCI (memory integrity)
        $vbsOn = ([string]$dg.VirtualizationBasedSecurityStatus -eq '2')
        Add-Check -Id 'DEV-1.6' -Result $(if ($vbsOn) { 'Pass' } else { 'Fail' }) `
            -Observed "VBS status $([string]$dg.VirtualizationBasedSecurityStatus); services running: $($running -join ', ')" `
            -Expected 'Virtualization-based security running'
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 2. Malware defense
    # ═════════════════════════════════════════════════════════════════════════

    $script:MpStatus = $null
    $script:MpPref   = $null
    try { $script:MpStatus = Get-MpComputerStatus -ErrorAction Stop } catch { }
    try { $script:MpPref   = Get-MpPreference   -ErrorAction Stop } catch { }

    Invoke-Check -Id 'DEV-2.1' -Body {
        if ($null -eq $script:MpStatus) {
            Add-Check -Id 'DEV-2.1' -Result 'NotAssessed' -Detail 'Get-MpComputerStatus unavailable — Defender may be replaced by a third-party AV.'
            return
        }
        $on = [bool]$script:MpStatus.RealTimeProtectionEnabled
        Add-Check -Id 'DEV-2.1' -Result $(if ($on) { 'Pass' } else { 'Fail' }) `
            -Observed "RealTimeProtectionEnabled=$on; AMRunningMode=$([string]$script:MpStatus.AMRunningMode)" `
            -Expected 'Real-time protection enabled' `
            -Detail 'AMRunningMode of "Passive" or "EDR Block Mode" means a third-party AV is primary; confirm that product is healthy separately.'
    }

    Invoke-Check -Id 'DEV-2.2' -Body {
        if ($null -eq $script:MpStatus) {
            Add-Check -Id 'DEV-2.2' -Result 'NotAssessed' -Detail 'Get-MpComputerStatus unavailable.'
            return
        }
        $tp = $false
        if ($script:MpStatus.PSObject.Properties['IsTamperProtected']) { $tp = [bool]$script:MpStatus.IsTamperProtected }
        Add-Check -Id 'DEV-2.2' -Result $(if ($tp) { 'Pass' } else { 'Fail' }) `
            -Observed "IsTamperProtected=$tp" -Expected 'Tamper protection enabled' `
            -Detail 'Without tamper protection, malware with admin rights can simply switch Defender off.'
    }

    Invoke-Check -Id 'DEV-2.3' -Body {
        if ($null -eq $script:MpStatus) {
            Add-Check -Id 'DEV-2.3' -Result 'NotAssessed' -Detail 'Get-MpComputerStatus unavailable.'
            return
        }
        $last = $script:MpStatus.AntivirusSignatureLastUpdated
        if ($null -eq $last) {
            Add-Check -Id 'DEV-2.3' -Result 'NotAssessed' -Detail 'Signature timestamp not reported.'
            return
        }
        $ageDays = [int]((Get-Date) - $last).TotalDays
        Add-Check -Id 'DEV-2.3' -Result $(if ($ageDays -le $MaxSignatureAgeDays) { 'Pass' } else { 'Fail' }) `
            -Observed "$ageDays day(s) old (updated $($last.ToString('yyyy-MM-dd')))" `
            -Expected "Updated within $MaxSignatureAgeDays day(s)"
    }

    Invoke-Check -Id 'DEV-2.4' -Body {
        if ($null -eq $script:MpPref) {
            Add-Check -Id 'DEV-2.4' -Result 'NotAssessed' -Detail 'Get-MpPreference unavailable.'
            return
        }
        # MAPSReporting: 0 Disabled, 1 Basic, 2 Advanced
        $maps = [int]$script:MpPref.MAPSReporting
        Add-Check -Id 'DEV-2.4' -Result $(if ($maps -ge 1) { 'Pass' } else { 'Fail' }) `
            -Observed "MAPSReporting=$maps" -Expected 'Basic (1) or Advanced (2)'
    }

    Invoke-Check -Id 'DEV-2.5' -Body {
        if ($null -eq $script:MpPref) {
            Add-Check -Id 'DEV-2.5' -Result 'NotAssessed' -Detail 'Get-MpPreference unavailable.'
            return
        }
        # PUAProtection: 0 Disabled, 1 Enabled (block), 2 Audit
        $pua = [int]$script:MpPref.PUAProtection
        Add-Check -Id 'DEV-2.5' -Result $(if ($pua -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "PUAProtection=$pua" -Expected 'Enabled in block mode (1)' `
            -Detail 'Audit mode (2) reports potentially unwanted applications but does not stop them.'
    }

    Invoke-Check -Id 'DEV-2.6' -Body {
        if ($null -eq $script:MpPref) {
            Add-Check -Id 'DEV-2.6' -Result 'NotAssessed' -Detail 'Get-MpPreference unavailable.'
            return
        }
        $ids     = @($script:MpPref.AttackSurfaceReductionRules_Ids)
        $actions = @($script:MpPref.AttackSurfaceReductionRules_Actions)
        if ($ids.Count -eq 0) {
            Add-Check -Id 'DEV-2.6' -Result 'Fail' -Observed 'No ASR rules configured' -Expected 'Key ASR rules in Block mode (1)'
            return
        }
        # Action 1 = Block, 2 = Audit, 6 = Warn
        $blocking = 0
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($i -lt $actions.Count -and [int]$actions[$i] -eq 1) { $blocking++ }
        }
        Add-Check -Id 'DEV-2.6' -Result $(if ($blocking -ge 1) { 'Pass' } else { 'Fail' }) `
            -Observed "$blocking of $($ids.Count) rule(s) in Block mode" `
            -Expected 'At least one ASR rule enforcing in Block mode' `
            -Detail 'Rules in Audit mode report the technique but do not stop it.'
    }

    Invoke-Check -Id 'DEV-2.7' -Body {
        if ($null -eq $script:MpPref) {
            Add-Check -Id 'DEV-2.7' -Result 'NotAssessed' -Detail 'Get-MpPreference unavailable.'
            return
        }
        # 0 Disabled, 1 Enabled, 2 Audit
        $cfa = [int]$script:MpPref.EnableControlledFolderAccess
        Add-Check -Id 'DEV-2.7' -Result $(if ($cfa -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "EnableControlledFolderAccess=$cfa" -Expected 'Enabled (1)' `
            -Detail 'Controlled folder access is the ransomware-specific control: it blocks untrusted processes writing to user document folders.'
    }

    Invoke-Check -Id 'DEV-2.8' -Body {
        $state = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -Name 'OnboardingState'
        if ($null -eq $state) {
            Add-Check -Id 'DEV-2.8' -Result 'Fail' -Observed 'No onboarding state present' `
                -Expected 'OnboardingState = 1' `
                -Detail 'Defender for Endpoint provides the EDR telemetry used to reconstruct an intrusion after the fact.'
            return
        }
        Add-Check -Id 'DEV-2.8' -Result $(if ([int]$state -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "OnboardingState=$state" -Expected '1 (onboarded)'
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 3. Network exposure
    # ═════════════════════════════════════════════════════════════════════════

    # -PolicyStore ActiveStore is the EFFECTIVE firewall configuration, with
    # Group Policy and Intune applied. Without it the cmdlet reads the local
    # persistent store, which a policy-managed machine overrides.
    # NotConfigured means the Windows default: firewall on, inbound blocked.
    Invoke-Check -Id 'DEV-3.1' -Body {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $off = @($profiles | Where-Object { [string]$_.Enabled -eq 'False' })
        if ($off.Count -eq 0) {
            Add-Check -Id 'DEV-3.1' -Result 'Pass' -Observed "All $($profiles.Count) profiles enabled"
        } else {
            Add-Check -Id 'DEV-3.1' -Result 'Fail' `
                -Observed "Disabled on: $(($off | ForEach-Object { [string]$_.Name }) -join ', ')" `
                -Expected 'Enabled on Domain, Private and Public'
        }
    }

    Invoke-Check -Id 'DEV-3.2' -Body {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $permissive = @($profiles | Where-Object { [string]$_.DefaultInboundAction -eq 'Allow' })
        if ($permissive.Count -eq 0) {
            Add-Check -Id 'DEV-3.2' -Result 'Pass' -Observed "Default inbound: $(($profiles | ForEach-Object { "$([string]$_.Name)=$([string]$_.DefaultInboundAction)" }) -join ', ') (NotConfigured is the Windows default, Block)"
        } else {
            Add-Check -Id 'DEV-3.2' -Result 'Fail' `
                -Observed "Not blocking by default: $(($permissive | ForEach-Object { "$([string]$_.Name)=$([string]$_.DefaultInboundAction)" }) -join ', ')" `
                -Expected 'DefaultInboundAction Block on all profiles'
        }
    }

    Invoke-Check -Id 'DEV-3.3' -Body {
        $smb1 = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        $featureOn = $null
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            if ($script:IsElevated) {
                try {
                    $f = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
                    $featureOn = ([string]$f.State -eq 'Enabled')
                } catch { }
            }
        }
        $enabled = $false
        if ($null -ne $smb1 -and [int]$smb1 -eq 1) { $enabled = $true }
        if ($featureOn -eq $true) { $enabled = $true }
        if ($null -eq $smb1 -and $null -eq $featureOn) {
            Add-Check -Id 'DEV-3.3' -Result 'NotAssessed' -Detail 'Neither the registry value nor the optional-feature state could be read.'
            return
        }
        Add-Check -Id 'DEV-3.3' -Result $(if ($enabled) { 'Fail' } else { 'Pass' }) `
            -Observed "SMB1 registry=$smb1; optional feature enabled=$featureOn" `
            -Expected 'SMBv1 not enabled' `
            -Detail 'SMBv1 is the protocol WannaCry and NotPetya spread over. It has no safe configuration.'
    }

    Invoke-Check -Id 'DEV-3.4' -Body {
        $llmnr = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
        if ($null -eq $llmnr) {
            Add-Check -Id 'DEV-3.4' -Result 'Fail' -Observed 'Policy not set (LLMNR on by default)' `
                -Expected 'EnableMulticast = 0' `
                -Detail 'LLMNR and NBT-NS poisoning is the standard opening move for internal credential capture (Responder).'
            return
        }
        Add-Check -Id 'DEV-3.4' -Result $(if ([int]$llmnr -eq 0) { 'Pass' } else { 'Fail' }) `
            -Observed "EnableMulticast=$llmnr" -Expected '0 (disabled)'
    }

    Invoke-Check -Id 'DEV-3.5' -Body {
        # The Group Policy value overrides the local one; RDP enabled by policy
        # with the local value still at 1 was reported as disabled.
        $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        $deny = Get-RegValue -Path $polKey -Name 'fDenyTSConnections'
        if ($null -eq $deny) { $deny = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' }
        if ($null -eq $deny -or [int]$deny -eq 1) {
            Add-Check -Id 'DEV-3.5' -Result 'NotApplicable' -Observed 'RDP disabled' `
                -Detail 'Remote Desktop is not accepting connections, so network-level authentication does not apply.'
            return
        }
        $nla = Get-RegValue -Path $polKey -Name 'UserAuthentication'
        if ($null -eq $nla) { $nla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' }
        # UserAuthentication absent in both places is the Windows default,
        # which requires NLA; only an explicit 0 turns it off.
        Add-Check -Id 'DEV-3.5' -Result $(if ($null -eq $nla -or [int]$nla -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "RDP enabled; UserAuthentication(NLA)=$nla" `
            -Expected 'NLA required (1) when RDP is enabled' `
            -Detail 'Without NLA the logon screen is reachable before authentication, which is both a brute-force and a pre-auth exploit surface.'
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 4. Accounts and privilege
    # ═════════════════════════════════════════════════════════════════════════

    Invoke-Check -Id 'DEV-4.1' -Body {
        if (-not (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-4.1' -Result 'NotAssessed' -Detail 'Get-LocalGroupMember unavailable.'
            return
        }
        $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $names = @($members | ForEach-Object { [string]$_.Name })
        # Reported, not judged: what counts as too many is a per-client decision.
        # The finding is the list; the tool decides what to do with it.
        Add-Check -Id 'DEV-4.1' -Result 'Info' `
            -Observed "$($names.Count) member(s): $($names -join ', ')" `
            -Expected 'Reviewed and minimal' `
            -Detail 'Inventory check. Review the list against who should hold local administrator rights on this machine.'
    }

    Invoke-Check -Id 'DEV-4.2' -Body {
        if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-4.2' -Result 'NotAssessed' -Detail 'Get-LocalUser unavailable.'
            return
        }
        # Match on the well-known RID suffix, not the name: the built-in account
        # is very often renamed, and matching on "Administrator" would then
        # report a clean pass on a machine where it is enabled under a new name.
        $builtin = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -like 'S-1-5-21-*-500' })
        if ($builtin.Count -eq 0) {
            Add-Check -Id 'DEV-4.2' -Result 'NotAssessed' -Detail 'Built-in administrator account (RID 500) not found.'
            return
        }
        $acct = $builtin[0]
        Add-Check -Id 'DEV-4.2' -Result $(if (-not $acct.Enabled) { 'Pass' } else { 'Fail' }) `
            -Observed "$([string]$acct.Name) enabled=$($acct.Enabled)" `
            -Expected 'Built-in administrator disabled'
    }

    Invoke-Check -Id 'DEV-4.3' -Body {
        if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-4.3' -Result 'NotAssessed' -Detail 'Get-LocalUser unavailable.'
            return
        }
        $guest = @(Get-LocalUser -ErrorAction Stop | Where-Object { [string]$_.SID -like 'S-1-5-21-*-501' })
        if ($guest.Count -eq 0) {
            Add-Check -Id 'DEV-4.3' -Result 'NotApplicable' -Detail 'Guest account (RID 501) not present.'
            return
        }
        Add-Check -Id 'DEV-4.3' -Result $(if (-not $guest[0].Enabled) { 'Pass' } else { 'Fail' }) `
            -Observed "$([string]$guest[0].Name) enabled=$($guest[0].Enabled)" -Expected 'Guest disabled'
    }

    Invoke-Check -Id 'DEV-4.4' -Body {
        # Windows LAPS (modern) and legacy Microsoft LAPS store state in
        # different places. Check both before concluding it is absent.
        $modern = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State' -Name 'LastPasswordUpdateTime'
        $policy = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory'
        $legacy = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -Name 'AdmPwdEnabled'
        # BackupDirectory 0 means Windows LAPS is DISABLED (1 = Entra ID,
        # 2 = Active Directory); a policy that exists with 0 is not LAPS, and
        # a last-rotation timestamp alone is history, not management.
        $present = ($null -ne $policy -and [int]$policy -in @(1, 2)) -or ($null -ne $legacy -and [int]$legacy -eq 1)
        Add-Check -Id 'DEV-4.4' -Result $(if ($present) { 'Pass' } else { 'Fail' }) `
            -Observed "Windows LAPS state=$modern policy=$policy; legacy AdmPwdEnabled=$legacy" `
            -Expected 'Windows LAPS BackupDirectory 1 (Entra ID) or 2 (Active Directory), or legacy LAPS enabled' `
            -Detail 'A shared local admin password means one recovered credential unlocks every device that shares it.'
    }

    Invoke-Check -Id 'DEV-4.5' -Body {
        if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-4.5' -Result 'NotAssessed' -Detail 'Get-LocalUser unavailable.'
            return
        }
        $never = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
        if ($never.Count -eq 0) {
            Add-Check -Id 'DEV-4.5' -Result 'Pass' -Observed 'No enabled local account has a non-expiring password'
        } else {
            Add-Check -Id 'DEV-4.5' -Result 'Fail' `
                -Observed "$($never.Count): $(($never | ForEach-Object { [string]$_.Name }) -join ', ')" `
                -Expected 'No enabled local account with PasswordNeverExpires' `
                -Detail 'A LAPS-managed account is the documented exception — record it if that is what these are.'
        }
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 5. Patch state
    # ═════════════════════════════════════════════════════════════════════════

    Invoke-Check -Id 'DEV-5.1' -Body {
        $ubr = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
        $dispVer = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'DisplayVersion'
        $build = $device.OSBuild
        Add-Check -Id 'DEV-5.1' -Result 'Info' `
            -Observed "$([string]$device.OSCaption) $dispVer build $build.$ubr" `
            -Expected 'A servicing branch still receiving security updates' `
            -Detail 'Inventory check. Whether this build is still supported is a lifecycle decision the assessment makes centrally, not something the endpoint can know.'
    }

    Invoke-Check -Id 'DEV-5.2' -Body {
        $latest = $null
        try {
            $hotfix = @(Get-HotFix -ErrorAction Stop | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending)
            if ($hotfix.Count -gt 0) { $latest = $hotfix[0].InstalledOn }
        } catch { }
        if ($null -eq $latest) {
            Add-Check -Id 'DEV-5.2' -Result 'NotAssessed' -Detail 'No dated hotfix records available (common on builds serviced by cumulative-update packages only).'
            return
        }
        $age = [int]((Get-Date) - $latest).TotalDays
        Add-Check -Id 'DEV-5.2' -Result $(if ($age -le $MaxPatchAgeDays) { 'Pass' } else { 'Fail' }) `
            -Observed "Last update $($latest.ToString('yyyy-MM-dd')), $age day(s) ago" `
            -Expected "An update within $MaxPatchAgeDays day(s)"
    }

    Invoke-Check -Id 'DEV-5.3' -Body {
        $pending = $false
        $reasons = New-Object System.Collections.ArrayList
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $pending = $true; $null = $reasons.Add('Component Based Servicing')
        }
        if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $pending = $true; $null = $reasons.Add('Windows Update')
        }
        $pfro = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
        if ($null -ne $pfro) { $pending = $true; $null = $reasons.Add('Pending file rename') }
        Add-Check -Id 'DEV-5.3' -Result $(if ($pending) { 'Fail' } else { 'Pass' }) `
            -Observed $(if ($pending) { "Reboot pending: $($reasons -join ', ')" } else { 'No reboot pending' }) `
            -Expected 'No pending reboot' `
            -Detail 'A patch that has been installed but not rebooted into is not yet protecting the machine.'
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 6. Session lock
    # ═════════════════════════════════════════════════════════════════════════

    Invoke-Check -Id 'DEV-6.1' -Body {
        $limit = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'
        if ($null -eq $limit -or [int]$limit -eq 0) {
            Add-Check -Id 'DEV-6.1' -Result 'Fail' -Observed 'InactivityTimeoutSecs not set (no machine inactivity lock)' `
                -Expected "Set, and no greater than $MaxInactivitySeconds seconds"
            return
        }
        Add-Check -Id 'DEV-6.1' -Result $(if ([int]$limit -le $MaxInactivitySeconds) { 'Pass' } else { 'Fail' }) `
            -Observed "InactivityTimeoutSecs=$limit" -Expected "<= $MaxInactivitySeconds seconds"
    }

    Invoke-Check -Id 'DEV-6.2' -Body {
        # Machine-wide policy for the interactive logon banner is not the same
        # thing; this checks the per-machine screen-saver policy where set.
        $secure = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure'
        if ($null -eq $secure) {
            Add-Check -Id 'DEV-6.2' -Result 'NotAssessed' `
                -Detail 'No machine-wide screen-saver policy. DEV-6.1 (machine inactivity limit) is the enforceable control; this one is per-user and may be set in the user hive.'
            return
        }
        Add-Check -Id 'DEV-6.2' -Result $(if ([string]$secure -eq '1') { 'Pass' } else { 'Fail' }) `
            -Observed "ScreenSaverIsSecure=$secure" -Expected '1 (password required on resume)'
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 7. Legacy surface and logging
    # ═════════════════════════════════════════════════════════════════════════

    Invoke-Check -Id 'DEV-7.1' -NeedsElevation -Body {
        if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
            Add-Check -Id 'DEV-7.1' -Result 'NotAssessed' -Detail 'Get-WindowsOptionalFeature unavailable (server SKU or Windows PowerShell absent).'
            return
        }
        $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop
        $on = ([string]$f.State -eq 'Enabled')
        Add-Check -Id 'DEV-7.1' -Result $(if ($on) { 'Fail' } else { 'Pass' }) `
            -Observed "PowerShell v2 engine: $([string]$f.State)" -Expected 'Disabled' `
            -Detail 'The v2 engine bypasses script block logging, AMSI and constrained language mode. It is a standard downgrade target.'
    }

    Invoke-Check -Id 'DEV-7.2' -Body {
        $sbl = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
        Add-Check -Id 'DEV-7.2' -Result $(if ($null -ne $sbl -and [int]$sbl -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "EnableScriptBlockLogging=$sbl" -Expected '1 (enabled)' `
            -Detail 'Script block logging is usually the only record of what a fileless PowerShell intrusion actually did.'
    }

    Invoke-Check -Id 'DEV-7.3' -Body {
        $noDrive = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
        # 0xFF (255) disables autorun on all drive types.
        Add-Check -Id 'DEV-7.3' -Result $(if ($null -ne $noDrive -and [int]$noDrive -eq 255) { 'Pass' } else { 'Fail' }) `
            -Observed "NoDriveTypeAutoRun=$noDrive" -Expected '255 (autorun disabled on all drive types)'
    }

    Invoke-Check -Id 'DEV-7.4' -Body {
        $wdac = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds'
        Add-Check -Id 'DEV-7.4' -Result $(if ($null -ne $wdac -and [int]$wdac -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "AllowProtectedCreds=$wdac" -Expected '1 (Restricted Admin / Credential Guard delegation protection)' `
            -Detail 'Limits credentials being left in memory on the machine an administrator connects TO.'
    }

    # ═════════════════════════════════════════════════════════════════════════
    # 8. Audit policy
    # ═════════════════════════════════════════════════════════════════════════

    Invoke-Check -Id 'DEV-8.1' -Body {
        $cmdline = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'
        Add-Check -Id 'DEV-8.1' -Result $(if ($null -ne $cmdline -and [int]$cmdline -eq 1) { 'Pass' } else { 'Fail' }) `
            -Observed "ProcessCreationIncludeCmdLine_Enabled=$cmdline" -Expected '1 (enabled)' `
            -Detail 'Without this, process-creation events record the binary but not its arguments, which is where the intent usually is.'
    }

    Invoke-Check -Id 'DEV-8.2' -NeedsElevation -Body {
        $out = & auditpol.exe /get /subcategory:"Process Creation" 2>$null
        if (-not $out) {
            Add-Check -Id 'DEV-8.2' -Result 'NotAssessed' -Detail 'auditpol returned nothing.'
            return
        }
        $text = ($out -join ' ')
        $on = ($text -match 'Success')
        Add-Check -Id 'DEV-8.2' -Result $(if ($on) { 'Pass' } else { 'Fail' }) `
            -Observed ($text.Trim() -replace '\s+', ' ') `
            -Expected 'Process Creation auditing includes Success'
    }

    # ── Assemble and write ───────────────────────────────────────────────────
    $counts = [ordered]@{
        Pass          = @($script:Checks | Where-Object { $_.Result -eq 'Pass' }).Count
        Fail          = @($script:Checks | Where-Object { $_.Result -eq 'Fail' }).Count
        NotApplicable = @($script:Checks | Where-Object { $_.Result -eq 'NotApplicable' }).Count
        NotAssessed   = @($script:Checks | Where-Object { $_.Result -eq 'NotAssessed' }).Count
        Error         = @($script:Checks | Where-Object { $_.Result -eq 'Error' }).Count
    }

    $result = [ordered]@{
        Schema        = $script:Schema
        ScriptVersion = $script:ScriptVersion
        CollectedAt   = (Get-Date).ToUniversalTime().ToString('o')
        Elevated      = $script:IsElevated
        Device        = $device
        Counts        = $counts
        Checks        = @($script:Checks)
    }

    if (-not $OutputPath) {
        $dir = Join-Path $env:ProgramData 'NRG'
        if (-not (Test-Path -LiteralPath $dir)) {
            $null = [System.IO.Directory]::CreateDirectory($dir)
        }
        $OutputPath = Join-Path $dir 'device-compliance.json'
    } else {
        $dir = Split-Path -Parent $OutputPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            $null = [System.IO.Directory]::CreateDirectory($dir)
        }
    }

    $json = $result | ConvertTo-Json -Depth 6
    # -Encoding utf8 on 5.1 writes a BOM; the ingesting side strips it.
    Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8

    Write-Output "NRG device compliance: $($counts.Pass) pass, $($counts.Fail) fail, $($counts.NotAssessed) not assessed."
    Write-Output "Written to $OutputPath"
    if (-not $script:IsElevated) {
        Write-Warning 'Not elevated — encryption, TPM, Secure Boot and audit-policy checks could not run. Results are PARTIAL.'
    }

    if ($PassThru) { Write-Output $result }

    if (-not $script:IsElevated) { exit 3 }
    if ($counts.Fail -gt 0)      { exit 2 }
    exit 0

} catch {
    Write-Error "NRG device compliance collector failed: $($_.Exception.Message)"
    exit 4
}

#Requires -Version 7.0
#
# Test-NRGControlDevice.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Turns endpoint check results into DEV-* findings, aggregated across
#          the fleet.
#
#          One finding per DEV control, not one per device. An assessment report
#          with 60 laptops x 35 checks is 2,100 rows nobody reads; what an
#          operator needs is "DEV-1.1 BitLocker: 41 of 60 failing" with the
#          hostnames attached, which is what AffectedObjects carries.
#
#          Aggregation rule, and the reason for it:
#            no device produced an assessable result  -> NotApplicable
#            every assessable device passes           -> Satisfied
#            some pass, some fail                     -> Partial
#            no assessable device passes              -> Gap
#
#          NotAssessed and Error results are excluded from the denominator
#          entirely. A check that could not run because the script was not
#          elevated is not a device that failed, and it is emphatically not a
#          device that passed — counting it either way is the false-clean-bill
#          -of-health bug in fleet form.
#
# Reads:   Device-Compliance
# Consumes: Config/device-controls.json for title, severity, NIST and remediation.
#

$script:NRGDeviceControls = $null

# An endpoint result older than this is not evidence about the device today: it is
# counted as not assessed (never a pass, never a failure), like a check the
# collector could not run. Matches the baseline's 'Weekly' freshness window.
$script:NRGDeviceResultMaxAgeDays = 8

function Get-NRGDeviceControlDefinitions {
    <#
        Loads Config/device-controls.json. Returns an empty array rather than
        throwing when absent — a deployment without the file should degrade to
        "no device controls", not to a failed assessment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:NRGDeviceControls -and -not $ConfigPath) { return $script:NRGDeviceControls }

    $moduleRoot = if ($script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $moduleRoot 'Config' 'device-controls.json' }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "device-controls.json not found at $path — DEV controls unavailable."
        return @()
    }
    if (-not $ConfigPath) {
        $resolved     = [System.IO.Path]::GetFullPath($path)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "device-controls.json resolved outside module root: $resolved"
        }
    }

    try {
        $data = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load device-controls.json: $($_.Exception.Message)"
        return @()
    }

    $defs = @(Get-NRGObjectField -Item $data -Key 'controls' -Default @())
    if (-not $ConfigPath) { $script:NRGDeviceControls = $defs }
    return $defs
}

function Test-NRGControlDevice {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Findings carry Category 'Endpoint' — the vocabulary Add-NRGFinding
    # enforces via ValidateSet, and the same bucket the INT controls use.
    # device-controls.json's own Group field is finer-grained grouping for
    # the config and the device documents, not a finding category.
    $defs = @(Get-NRGDeviceControlDefinitions)
    if ($defs.Count -eq 0) { return }

    $raw = Get-NRGRawData -Key 'Device-Compliance'

    # No device results supplied at all. Every DEV control reports
    # NotApplicable with a prompt, rather than being silently absent from the
    # report — an operator who forgot -DeviceResults should see that the
    # endpoint half did not run, not a report that simply omits it.
    if (-not $raw -or -not $raw.Success) {
        foreach ($c in $defs) {
            Add-NRGFinding -ControlId ([string]$c.ControlId) -State 'NotApplicable' `
                -Category 'Endpoint' -Title ([string]$c.Title) `
                -Detail 'No endpoint results supplied. Run Device\Invoke-NRGDeviceCompliance.ps1 on the devices and re-run with -DeviceResults <folder>.' `
                -FrameworkIds (Get-NRGDeviceFrameworkIds -Control $c)
        }
        return
    }

    $status  = [string](Get-NRGNestedProperty -Object $raw -Path 'Data.SectionStatus.DeviceResults' -Default 'Collected')
    $devices = @(Get-NRGNestedProperty -Object $raw -Path 'Data.Devices' -Default @())

    if ($status -ne 'Collected' -or $devices.Count -eq 0) {
        $why = if ($status -eq 'Failed') {
            'the endpoint result files could not be read (see Exceptions)'
        } else {
            'no endpoint result files were supplied'
        }
        foreach ($c in $defs) {
            Add-NRGFinding -ControlId ([string]$c.ControlId) -State 'NotApplicable' `
                -Category 'Endpoint' -Title ([string]$c.Title) `
                -Detail "Endpoint compliance not assessed: $why." `
                -FrameworkIds (Get-NRGDeviceFrameworkIds -Control $c)
        }
        return
    }

    $total       = $devices.Count
    $notElevated = @($devices | Where-Object { -not $_.Elevated }).Count

    # Age of each device's result. An unreadable timestamp is treated as stale:
    # a result whose age cannot be shown is not shown to be current.
    $now = (Get-Date).ToUniversalTime()
    $staleAge = @{}
    foreach ($d in $devices) {
        $host = ([string](Get-NRGObjectField -Item $d -Key 'Hostname' -Default '')).ToUpperInvariant()
        $ts = [datetime]::MinValue
        $ok = [datetime]::TryParse([string](Get-NRGObjectField -Item $d -Key 'CollectedAt' -Default ''), [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$ts)
        if (-not $ok) { $staleAge[$host] = -1 }
        elseif (($now - $ts.ToUniversalTime()).TotalDays -gt $script:NRGDeviceResultMaxAgeDays) { $staleAge[$host] = [int][math]::Floor(($now - $ts.ToUniversalTime()).TotalDays) }
    }
    $staleCount = $staleAge.Count

    # The fleet the results should cover: the managed Windows devices Intune
    # reported, when it did. Without a reference, completeness cannot be shown.
    $expectedFleet = $null
    $intune = Get-NRGRawData -Key 'Intune-DeviceCompliance'
    if ($intune -and (Get-NRGObjectField -Item $intune -Key 'Success' -Default $false)) {
        $byPlat = Get-NRGNestedProperty -Object $intune -Path 'Data.OSComplianceSummary.ByPlatform' -Default $null
        $secOk = [string](Get-NRGNestedProperty -Object $intune -Path 'Data.SectionStatus.OSComplianceSummary' -Default 'Collected')
        if ($null -ne $byPlat -and $secOk -ne 'Failed') {
            $names = if ($byPlat -is [System.Collections.IDictionary]) { @($byPlat.Keys) } else { @($byPlat.PSObject.Properties | ForEach-Object { $_.Name }) }
            $sum = 0
            foreach ($n in $names) { if ($n -match '^Windows') { $sum += [int](Get-NRGObjectField -Item $byPlat -Key $n -Default 0) } }
            $expectedFleet = $sum
        }
    }
    $covByCid = @{}
    $findingsBefore = @(Get-NRGFindings).Count

    # Index every device's checks by ID once, rather than re-scanning the whole
    # fleet for each of 35 controls.
    $byCheck = @{}
    foreach ($d in $devices) {
        foreach ($chk in @(Get-NRGObjectField -Item $d -Key 'Checks' -Default @())) {
            $id = [string](Get-NRGObjectField -Item $chk -Key 'Id' -Default '')
            if (-not $id) { continue }
            if (-not $byCheck.ContainsKey($id)) { $byCheck[$id] = [System.Collections.Generic.List[object]]::new() }
            $hostKey = ([string](Get-NRGObjectField -Item $d -Key 'Hostname' -Default '')).ToUpperInvariant()
            $isStale = $staleAge.ContainsKey($hostKey)
            $byCheck[$id].Add([ordered]@{
                Hostname = [string](Get-NRGObjectField -Item $d   -Key 'Hostname' -Default '')
                Result   = $(if ($isStale) { 'NotAssessed' } else { [string](Get-NRGObjectField -Item $chk -Key 'Result' -Default '') })
                Observed = [string](Get-NRGObjectField -Item $chk -Key 'Observed' -Default '')
                Detail   = $(if ($isStale) { 'Stale result: not counted as a pass or a failure.' } else { [string](Get-NRGObjectField -Item $chk -Key 'Detail' -Default '') })
            })
        }
    }

    foreach ($c in $defs) {
        $cid   = [string]$c.ControlId
        $cits  = Get-NRGDeviceFrameworkIds -Control $c
        # Assigned in two statements, NOT as `$rows = if (...) { @(...) } else { @() }`.
        # An if-block yielding an EMPTY array assigns $null, because the pipeline
        # enumerates the result and an empty array enumerates to nothing. $rows
        # was then $null for every control the fixture did not contain, and
        # $rows.Count threw under StrictMode.
        $rows = @()
        if ($byCheck.ContainsKey($cid)) { $rows = @($byCheck[$cid]) }

        # Inventory checks (local administrators, OS build) record what is
        # there; they judge nothing. Older endpoint results reported them as
        # Pass, which gave every device a clean result for them.
        if ([bool](Get-NRGObjectField -Item $c -Key 'Inventory' -Default $false)) {
            $seen = @($rows | Where-Object { $_.Result -in @('Info','Pass','Fail') })
            $inv  = @($seen | ForEach-Object { [ordered]@{ Hostname = $_.Hostname; Observed = $_.Observed } })
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                -Category 'Endpoint' -Title ([string]$c.Title) `
                -Detail "Requires manual verification: this is an inventory of $($seen.Count) of $total device(s), not a pass or fail. Review each device's entry against what it should be." `
                -CurrentValue "$($seen.Count) of $total device(s) recorded" `
                -AffectedObjects $inv -FrameworkIds $cits
            continue
        }

        $pass        = @($rows | Where-Object { $_.Result -eq 'Pass' })
        $fail        = @($rows | Where-Object { $_.Result -eq 'Fail' })
        $na          = @($rows | Where-Object { $_.Result -eq 'NotApplicable' })
        $notAssessed = @($rows | Where-Object { $_.Result -in @('NotAssessed','Error') })
        $assessed    = $pass.Count + $fail.Count

        # Devices whose result file carried no entry for this check at all —
        # an older endpoint script version, most likely. Tracked separately so
        # a version skew across the fleet is visible rather than silently
        # shrinking the denominator.
        $missing = $total - $rows.Count

        $blockedNote = ''
        if ($notAssessed.Count -gt 0) {
            $blockedNote = " $($notAssessed.Count) device(s) could not run this check"
            if ($notElevated -gt 0 -and [bool]$c.RequiresElevation) {
                $blockedNote += " (the collector ran without administrative rights on $notElevated device(s))"
            }
            $blockedNote += '.'
        }
        if ($staleCount -gt 0) {
            $blockedNote += " $staleCount device(s) reported results older than $($script:NRGDeviceResultMaxAgeDays) days (or with no readable date) and were not counted."
        }
        if ($missing -gt 0) {
            $blockedNote += " $missing device(s) reported no result for this check — check the endpoint script version."
        }
        # Structured coverage for this check: what the verdict rests on. The
        # baseline reads it to decide whether an all-pass result may be labeled
        # Effective.
        $verdicts = $pass.Count + $fail.Count + $na.Count
        $reasons = [System.Collections.Generic.List[string]]::new()
        if ($notAssessed.Count -gt 0) { $reasons.Add("$($notAssessed.Count) device(s) could not run this check") }
        if ($missing -gt 0)           { $reasons.Add("$missing device(s) reported no result for this check") }
        if ($staleCount -gt 0)        { $reasons.Add("$staleCount device(s) reported results older than $($script:NRGDeviceResultMaxAgeDays) days") }
        if ($null -eq $expectedFleet) { $reasons.Add('the expected fleet size is not known (no Intune managed-device count)') }
        elseif ($total -lt $expectedFleet) { $reasons.Add("$total of $expectedFleet managed Windows devices reported") }
        $covByCid[$cid] = [ordered]@{
            Devices       = $total
            Verdicts      = $verdicts
            NotAssessed   = $notAssessed.Count
            Missing       = $missing
            Stale         = $staleCount
            ExpectedFleet = $expectedFleet
            Complete      = ($reasons.Count -eq 0)
            Reasons       = @($reasons)
        }

        if ($assessed -eq 0) {
            # Two different reasons produce zero assessed devices, and conflating
            # them misleads. "RDP is disabled on every machine" is a genuine
            # non-applicability and good news; "the collector could not read
            # BitLocker anywhere" is a blind spot that needs fixing. Both report
            # NotApplicable — neither may read as a pass — but the operator has
            # to be able to tell which one they are looking at.
            $detail = if ($na.Count -gt 0 -and $notAssessed.Count -eq 0 -and $missing -eq 0) {
                "This check does not apply to any of the $total assessed device(s)."
            } else {
                "No device produced an assessable result for this check.$blockedNote"
            }
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                -Category 'Endpoint' -Title ([string]$c.Title) `
                -Detail $detail.Trim() `
                -CurrentValue "0 of $total device(s) assessed" `
                -FrameworkIds $cits
            continue
        }

        $affected = @($fail | ForEach-Object {
            [ordered]@{ Hostname = $_.Hostname; Observed = $_.Observed }
        })

        if ($fail.Count -eq 0) {
            Add-NRGFinding -ControlId $cid -State 'Satisfied' `
                -Category 'Endpoint' -Title ([string]$c.Title) -Severity 'Informational' `
                -Detail ("All $($pass.Count) assessed device(s) pass.$blockedNote").Trim() `
                -CurrentValue "$($pass.Count) of $assessed assessed device(s) compliant" `
                -FrameworkIds $cits
        }
        elseif ($pass.Count -eq 0) {
            Add-NRGFinding -ControlId $cid -State 'Gap' `
                -Category 'Endpoint' -Title ([string]$c.Title) -Severity ([string]$c.Severity) `
                -Detail ("$($fail.Count) of $assessed assessed device(s) fail this check — none pass.$blockedNote " +
                         [string]$c.BusinessRisk).Trim() `
                -CurrentValue "0 of $assessed compliant" `
                -RequiredValue 'All managed devices compliant' `
                -Remediation ([string]$c.Remediation) `
                -AffectedObjects $affected `
                -FrameworkIds $cits
        }
        else {
            Add-NRGFinding -ControlId $cid -State 'Partial' `
                -Category 'Endpoint' -Title ([string]$c.Title) -Severity ([string]$c.Severity) `
                -Detail ("$($fail.Count) of $assessed assessed device(s) fail this check.$blockedNote " +
                         [string]$c.BusinessRisk).Trim() `
                -CurrentValue "$($pass.Count) of $assessed compliant" `
                -RequiredValue 'All managed devices compliant' `
                -Remediation ([string]$c.Remediation) `
                -AffectedObjects $affected `
                -FrameworkIds $cits
        }
    }

    # Attach each finding's coverage (in place; Add-NRGFinding's record shape is
    # shared by every control, so the endpoint half adds its own field).
    $all = @(Get-NRGFindings)
    for ($i = $findingsBefore; $i -lt $all.Count; $i++) {
        $f = $all[$i]
        if ($covByCid.ContainsKey([string]$f.ControlId)) {
            Add-Member -InputObject $f -NotePropertyName 'Coverage' -NotePropertyValue $covByCid[[string]$f.ControlId] -Force
        }
    }
}

function Get-NRGDeviceFrameworkIds {
    <#
        Builds the flattened "NIST:AC-2" citation strings the family rollup and
        the standalone matrix parse. Without these, a DEV finding is scored in
        the tenant total but invisible in every NIST view — the one place the
        operator is actually looking.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Control
    )

    Set-StrictMode -Version Latest
    $nist = @(Get-NRGObjectField -Item $Control -Key 'Nist' -Default @())
    if ($nist.Count -eq 0) { return @() }
    return @('NIST:' + (($nist | ForEach-Object { [string]$_ }) -join ', '))
}

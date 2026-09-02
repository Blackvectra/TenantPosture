#Requires -Version 7.0
#
# Invoke-NRGCollectDeviceCompliance.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Ingests the JSON result files written by
#          Device/Invoke-NRGDeviceCompliance.ps1 on the endpoints, and publishes
#          them as the `Device-Compliance` raw-data key.
#
#          This collector reads FILES, not a tenant. There is no Graph call and
#          no endpoint contact — the endpoint script already ran, the RMM already
#          collected its output, and this turns a folder of those files into
#          fleet-level raw data.
#
# Sets:    Device-Compliance
# Reads:   a folder of *.json written by the endpoint collector.
# Scopes:  none. No Graph, no EXO.
#

function Invoke-NRGCollectDeviceCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $ResultsPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $result = [ordered]@{
        CollectorId = 'Device-Compliance'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Data        = [ordered]@{
            Devices       = @()
            DeviceCount   = 0
            ElevatedCount = 0
            SourcePath    = [string]$ResultsPath
            # Same contract as every other multi-query collector: an empty
            # Devices list is ambiguous between "no files supplied" and "the
            # files were unreadable", and the evaluators must be able to tell
            # those apart before concluding anything.
            SectionStatus = @{ DeviceResults = 'NotRun' }
        }
    }

    try {
        $files = @()
        if (Test-Path -LiteralPath $ResultsPath -PathType Container) {
            $files = @(Get-ChildItem -LiteralPath $ResultsPath -Filter '*.json' -File -ErrorAction Stop)
        } elseif (Test-Path -LiteralPath $ResultsPath -PathType Leaf) {
            $files = @(Get-Item -LiteralPath $ResultsPath -ErrorAction Stop)
        } else {
            $result.Data.SectionStatus.DeviceResults = 'Failed'
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Device-Compliance' -Message "Device results path not found: $ResultsPath"
            }
            Set-NRGRawData -Key 'Device-Compliance' -Data $result
            if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
                Register-NRGCoverage -Family 'Device' -Status 'Failed' -Note 'Device results path not found.'
            }
            return
        }

        $devices  = [System.Collections.Generic.List[object]]::new()
        $rejected = 0

        foreach ($f in $files) {
            try {
                # -Raw then ConvertFrom-Json: Windows PowerShell 5.1 writes a BOM
                # with -Encoding UTF8, and ConvertFrom-Json chokes on a leading
                # BOM. Trim it rather than requiring the endpoint to write
                # BOM-less UTF-8, which 5.1 cannot do without extra ceremony.
                $raw = Get-Content -LiteralPath $f.FullName -Raw -Encoding utf8 -ErrorAction Stop
                $raw = $raw.TrimStart([char]0xFEFF)
                $obj = $raw | ConvertFrom-Json -ErrorAction Stop

                $schema = [string](Get-NRGObjectField -Item $obj -Key 'Schema' -Default '')
                if ($schema -notmatch '^nrg-device-compliance/') {
                    # Not one of ours. Skipped loudly rather than parsed
                    # optimistically — a stray JSON in the collection folder must
                    # not become a device with no checks, which would read as a
                    # device that passed nothing.
                    $rejected++
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'Device-Compliance' `
                            -Message "Skipped $($f.Name): not a device-compliance result (schema '$schema')."
                    }
                    continue
                }

                $dev = Get-NRGObjectField -Item $obj -Key 'Device' -Default $null
                $devices.Add([ordered]@{
                    File        = [string]$f.Name
                    Hostname    = [string](Get-NRGObjectField -Item $dev -Key 'Hostname' -Default $f.BaseName)
                    OSCaption   = [string](Get-NRGObjectField -Item $dev -Key 'OSCaption' -Default '')
                    OSBuild     = [string](Get-NRGObjectField -Item $dev -Key 'OSBuild'   -Default '')
                    Serial      = [string](Get-NRGObjectField -Item $dev -Key 'Serial'    -Default '')
                    JoinType    = [string](Get-NRGObjectField -Item $dev -Key 'JoinType'  -Default 'Unknown')
                    CollectedAt = [string](Get-NRGObjectField -Item $obj -Key 'CollectedAt' -Default '')
                    Elevated    = [bool]  (Get-NRGObjectField -Item $obj -Key 'Elevated'    -Default $false)
                    Checks      = @(Get-NRGObjectField -Item $obj -Key 'Checks' -Default @())
                })
            } catch {
                $rejected++
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Device-Compliance' `
                        -Message "Could not read $($f.Name): $($_.Exception.Message)"
                }
            }
        }

        $result.Data.Devices       = $devices.ToArray()
        $result.Data.DeviceCount   = $devices.Count
        $result.Data.ElevatedCount = @($devices | Where-Object { $_.Elevated }).Count
        $result.Data.RejectedFiles = $rejected

        # Collected means the folder was read. Zero usable devices from a folder
        # that had files in it is a Failed section, not an empty one — otherwise
        # every DEV control reports a confident NotApplicable on what is really
        # a broken collection.
        if ($devices.Count -gt 0) {
            $result.Data.SectionStatus.DeviceResults = 'Collected'
        } elseif ($files.Count -gt 0) {
            $result.Data.SectionStatus.DeviceResults = 'Failed'
        } else {
            $result.Data.SectionStatus.DeviceResults = 'NotRun'
        }

        $result.Success = $true

    } catch {
        $result.Data.SectionStatus.DeviceResults = 'Failed'
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Device-Compliance' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Device-Compliance' -Data $result
    if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
        Register-NRGCoverage -Family 'Device' -Status $(if ($result.Success) { 'Collected' } else { 'Failed' }) -Note "$($result.Data.DeviceCount) device result(s) ingested."
    }
}

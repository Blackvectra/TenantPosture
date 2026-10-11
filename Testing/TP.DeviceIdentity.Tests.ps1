#Requires -Version 7.0
#
# TP.DeviceIdentity.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# An endpoint result file is written by whatever runs on an endpoint, so a file
# that claims another machine's host name must not replace that machine's
# result. A device is its host name AND its serial number; one name with two
# serials is a conflict that counts as neither a pass nor a failure. The
# schema is accepted under its current and its earlier name, major version 1.

Describe 'Endpoint result identity' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Now = (Get-Date).ToUniversalTime()
        function script:Result { param([string] $Name, [string] $Serial, [datetime] $At, [string] $Bitlocker, [string] $Schema = 'tp-device-compliance/1.0')
            [ordered]@{ Schema = $Schema; CollectedAt = $At.ToString('o'); Elevated = $true
                Device = [ordered]@{ Hostname = $Name; Serial = $Serial; OSCaption = 'Windows 11 Pro'; OSBuild = '22631'; JoinType = 'EntraJoined' }
                Checks = @([ordered]@{ Id = 'DEV-1.1'; Result = $Bitlocker; Observed = "BitLocker $Bitlocker"; Detail = 'x' }) } | ConvertTo-Json -Depth 5 }
        function script:Run { param([string] $Dir) Clear-TPState; Invoke-TPCollectDeviceCompliance -ResultsPath $Dir | Out-Null; Test-TPControlDevice | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq 'DEV-1.1' })[0] }
        function script:NewDir { param([string] $N) $d = Join-Path $TestDrive $N; New-Item -ItemType Directory -Path $d -Force | Out-Null; $d }
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'a newer file claiming another machine''s host name with a different serial does not replace its verdict' {
        $d = NewDir 'spoof'
        Set-Content -LiteralPath (Join-Path $d 'LAPTOP-B.json') -Value (Result -Name 'LAPTOP-B' -Serial 'S-B' -At $script:Now.AddHours(-2) -Bitlocker 'Fail') -Encoding utf8
        Set-Content -LiteralPath (Join-Path $d 'LAPTOP-A.json') -Value (Result -Name 'laptop-b' -Serial 'S-A' -At $script:Now.AddMinutes(-1) -Bitlocker 'Pass') -Encoding utf8
        $f = Run $d
        $f.State | Should -Not -Be 'Satisfied' -Because 'the genuine failing result must not be superseded by a file from another device'
        $f.State | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'reported by more than one device'
        $raw = Get-TPRawData -Key 'Device-Compliance'
        @($raw.Data.ConflictedHosts) | Should -Be @('LAPTOP-B')
        @($raw.Data.Devices).Count | Should -Be 2
        @($raw.Data.Devices | Where-Object { $_.Conflict }).Count | Should -Be 2
        ($f.PSObject.Properties['Coverage'].Value)['Conflicted'] | Should -Be 1
        ($f.PSObject.Properties['Coverage'].Value)['Complete'] | Should -BeFalse
    }

    It 'the same device reporting twice is still de-duplicated to its latest result' {
        $d = NewDir 'dupe'
        Set-Content -LiteralPath (Join-Path $d 'old.json') -Value (Result -Name 'PC-1' -Serial 'S-1' -At $script:Now.AddHours(-3) -Bitlocker 'Fail') -Encoding utf8
        Set-Content -LiteralPath (Join-Path $d 'new.json') -Value (Result -Name 'pc-1' -Serial 's-1' -At $script:Now.AddHours(-1) -Bitlocker 'Pass') -Encoding utf8
        $f = Run $d
        $f.State | Should -Be 'Satisfied'
        $raw = Get-TPRawData -Key 'Device-Compliance'
        $raw.Data.SupersededFiles | Should -Be 1
        @($raw.Data.ConflictedHosts).Count | Should -Be 0
    }

    It 'a result with no serial beside one with a serial for the same name is a conflict' {
        $d = NewDir 'noserial'
        Set-Content -LiteralPath (Join-Path $d 'a.json') -Value (Result -Name 'PC-2' -Serial 'S-2' -At $script:Now.AddHours(-2) -Bitlocker 'Fail') -Encoding utf8
        Set-Content -LiteralPath (Join-Path $d 'b.json') -Value (Result -Name 'PC-2' -Serial '' -At $script:Now.AddHours(-1) -Bitlocker 'Pass') -Encoding utf8
        (Run $d).State | Should -Be 'NotApplicable'
    }

    It 'accepts the earlier nrg- schema name at major version 1 and refuses another major version' {
        $d = NewDir 'schema'
        Set-Content -LiteralPath (Join-Path $d 'legacy.json') -Value (Result -Name 'PC-3' -Serial 'S-3' -At $script:Now.AddHours(-1) -Bitlocker 'Pass' -Schema 'nrg-device-compliance/1.0') -Encoding utf8
        Set-Content -LiteralPath (Join-Path $d 'future.json') -Value (Result -Name 'PC-4' -Serial 'S-4' -At $script:Now.AddHours(-1) -Bitlocker 'Pass' -Schema 'tp-device-compliance/2.0') -Encoding utf8
        $f = Run $d
        $f.State | Should -Be 'Satisfied'
        $raw = Get-TPRawData -Key 'Device-Compliance'
        $raw.Data.DeviceCount | Should -Be 1
        $raw.Data.RejectedFiles | Should -Be 1
        @(Get-TPExceptions | Where-Object { $_.Message -match 'unsupported device-compliance schema version' }).Count | Should -Be 1
    }
}

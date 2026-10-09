#Requires -Version 7.0
#
# TP.DeviceTruth.Tests.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Pins the endpoint (DEV-*) verdicts: one result per device (latest wins),
# inventory checks never pass, and the endpoint script reads the effective
# firewall store, the Group Policy RDP value and the LAPS backup directory.
#
# Data keys: Device-Compliance (Invoke-TPCollectDeviceCompliance).
#

Describe 'Endpoint compliance results are read truthfully' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Endpoint = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Device/Invoke-TPDeviceCompliance.ps1') -Raw
        # Relative to now: an endpoint result older than the freshness window is not
        # counted, so fixed calendar dates would turn these tests stale on their own.
        $script:Recent = (Get-Date).ToUniversalTime().AddDays(-1).ToString('o')
        $script:Old    = (Get-Date).ToUniversalTime().AddDays(-200).ToString('o')
        function script:Result { param([string] $Name, [string] $At, [object[]] $Checks)
            [ordered]@{ Schema = 'tp-device-compliance/1'; CollectedAt = $At; Elevated = $true; Device = @{ Hostname = $Name }; Checks = $Checks } | ConvertTo-Json -Depth 5 }
        function script:Verdict { param([string] $Cid) Test-TPControlDevice | Out-Null; @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }
    BeforeEach { Clear-TPState }
    AfterAll   { Clear-TPState }

    It 'keeps only the latest result per device (a fixed laptop was still counted as failing)' {
        $dir = Join-Path $TestDrive 'dupes'; New-Item -ItemType Directory -Path $dir | Out-Null
        Result 'LAPTOP-01' $script:Old @(@{ Id = 'DEV-1.1'; Result = 'Fail'; Observed = 'off' }) | Set-Content (Join-Path $dir 'LAPTOP-01-march.json')
        Result 'laptop-01' $script:Recent @(@{ Id = 'DEV-1.1'; Result = 'Pass'; Observed = 'on' })  | Set-Content (Join-Path $dir 'LAPTOP-01-sept.json')
        Result 'LAPTOP-02' $script:Recent @(@{ Id = 'DEV-1.1'; Result = 'Pass'; Observed = 'on' })  | Set-Content (Join-Path $dir 'LAPTOP-02.json')
        Invoke-TPCollectDeviceCompliance -ResultsPath $dir | Out-Null
        $raw = Get-TPRawData -Key 'Device-Compliance'
        $raw.Data.DeviceCount | Should -Be 2
        $raw.Data.SupersededFiles | Should -Be 1
        (Verdict 'DEV-1.1').State | Should -Be 'Satisfied'
    }

    It 'inventory checks (local administrators, OS build) are never a pass, even from older results that said Pass' {
        $dir = Join-Path $TestDrive 'inv'; New-Item -ItemType Directory -Path $dir | Out-Null
        Result 'PC1' $script:Recent @(@{ Id = 'DEV-4.1'; Result = 'Pass'; Observed = '2 member(s)' }, @{ Id = 'DEV-5.1'; Result = 'Info'; Observed = 'Windows 11 24H2' }) | Set-Content (Join-Path $dir 'PC1.json')
        Invoke-TPCollectDeviceCompliance -ResultsPath $dir | Out-Null
        foreach ($cid in 'DEV-4.1','DEV-5.1') {
            $f = Verdict $cid
            $f.State | Should -Be 'NotApplicable' -Because $cid
            $f.Detail | Should -Match 'requires manual verification'
        }
    }

    It 'the endpoint script reads the effective firewall store, the Group Policy RDP value and the LAPS backup directory' {
        @([regex]::Matches($script:Endpoint, 'Get-NetFirewallProfile -PolicyStore ActiveStore')).Count | Should -Be 2
        $script:Endpoint | Should -Match ([regex]::Escape('Policies\Microsoft\Windows NT\Terminal Services'))
        $script:Endpoint | Should -Match '\[int\]\$policy -in @\(1, 2\)' -Because 'BackupDirectory 0 means Windows LAPS is disabled'
        $script:Endpoint | Should -Match "Id 'DEV-4.1' -Result 'Info'"
        $script:Endpoint | Should -Match "Id 'DEV-5.1' -Result 'Info'"
    }
}

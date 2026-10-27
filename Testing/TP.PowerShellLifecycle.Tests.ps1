#Requires -Version 7.0
#
# TP.PowerShellLifecycle.Tests.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Pin Get-TPPowerShellSupportStatus and Config/powershell-lifecycle.json: the
#   dates are Microsoft's (PowerShell Support Lifecycle page), the warning fires before
#   and after end of support and never on a supported release, a preview is never called
#   supported, an unlisted release is unknown (never supported), and the warning is
#   wired into the entry point, the distribution-list scan, the installer and
#   Get-TPModuleHealth. A warning only: the run is never refused for it.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:RepoRoot 'Lib' 'Get-TPModuleInstallScope.ps1')
    $script:LifePath = Join-Path $script:RepoRoot 'Config' 'powershell-lifecycle.json'
    $script:Life     = Get-Content -LiteralPath $script:LifePath -Raw | ConvertFrom-Json
    function script:Status([string] $v, [string] $asOf) {
        Get-TPPowerShellSupportStatus -PSVersion $v -AsOf ([datetime]::ParseExact($asOf, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture)) -Path $script:LifePath
    }
}

Describe 'PowerShell lifecycle catalog' {
    It 'cites Microsoft''s PowerShell Support Lifecycle page' {
        $script:Life.source | Should -Be 'https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle'
        $script:Life.sourceRetrieved | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }
    It 'carries the end-of-support dates Microsoft publishes for 7.4, 7.5 and 7.6' {
        $d = @{}; foreach ($r in $script:Life.releases) { $d[[string]$r.Line] = [string]$r.EndOfSupport }
        $d['7.4'] | Should -Be '2026-11-10'
        $d['7.5'] | Should -Be '2026-11-10'
        $d['7.6'] | Should -Be '2028-11-14'
    }
    It 'has one well-formed row per release line' {
        $lines = @($script:Life.releases | ForEach-Object { [string]$_.Line })
        $lines.Count | Should -Be @($lines | Sort-Object -Unique).Count
        foreach ($r in $script:Life.releases) { [string]$r.EndOfSupport | Should -Match '^\d{4}-\d{2}-\d{2}$' }
    }
}

Describe 'Get-TPPowerShellSupportStatus' {
    It 'is quiet on a supported release outside the warning window' {
        $r = Status '7.6.6' '2026-10-27'
        $r.State | Should -Be 'Supported'; $r.Level | Should -Be 'None'
    }
    It 'warns inside the window, with the date and the upgrade command' {
        $r = Status '7.4.13' '2026-10-27'
        $r.State | Should -Be 'EndingSoon'; $r.Level | Should -Be 'Warning'
        $r.Text | Should -Match '2026-11-10'; $r.Text | Should -Match 'winget install --id Microsoft.PowerShell'
        (Status '7.5.4' '2026-10-27').State | Should -Be 'EndingSoon'
    }
    It 'counts the end-of-support day itself as still supported' {
        (Status '7.4.1' '2026-11-10').State | Should -Be 'EndingSoon'
        (Status '7.4.1' '2026-11-11').State | Should -Be 'EndOfSupport'
    }
    It 'warns after end of support' {
        $r = Status '7.2.24' '2026-10-27'
        $r.State | Should -Be 'EndOfSupport'; $r.Level | Should -Be 'Warning'; $r.Text | Should -Match 'no longer receives security updates'
    }
    It 'never calls a preview supported' {
        $r = Status '7.7.0-preview.3' '2026-10-27'
        $r.State | Should -Be 'Preview'; $r.Level | Should -Be 'Warning'
    }
    It 'reports a release line it does not know as unknown, never supported' {
        $r = Status '8.0.0' '2026-10-27'
        $r.State | Should -Be 'Unknown'; $r.Text | Should -Match 'not checked'
    }
    It 'reports an unreadable lifecycle file as not checked' {
        $r = Get-TPPowerShellSupportStatus -PSVersion '7.4.1' -Path (Join-Path $TestDrive 'missing.json')
        $r.State | Should -Be 'Unknown'; $r.Text | Should -Match 'not checked'
    }
    It 'accepts the running shell''s own SemanticVersion' {
        { Get-TPPowerShellSupportStatus -Path $script:LifePath } | Should -Not -Throw
    }
}

Describe 'PowerShell lifecycle warning is wired in, as a warning' {
    It 'is called by the entry point (full run and distribution-list scan), the installer and the health check' {
        $ep = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        ([regex]::Matches($ep, 'Get-TPPowerShellSupportStatus')).Count | Should -BeGreaterOrEqual 2
        Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Install-TPPrerequisites.ps1') -Raw | Should -Match 'Get-TPPowerShellSupportStatus'
        Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Get-TPModuleHealth.ps1') -Raw | Should -Match 'PowerShellSupport\s*=\s*\$psSupport'
    }
    It 'never exits the run on the lifecycle status' {
        $ep = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $ep | Should -Not -Match 'psSupport[^\r\n]*exit'
    }
}

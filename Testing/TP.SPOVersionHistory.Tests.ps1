#Requires -Version 7.0
#
# TP.SPOVersionHistory.Tests.ps1
#
# Proves SPO-3.3 (OneDrive/SharePoint version history — ransomware recovery)
# genuinely discriminates on the org-wide Get-SPOTenant version default:
# automatic trimming or an adequate major-version limit => Satisfied; a low
# manual limit with auto-trim off => Gap; no Get-SPOTenant data => NotApplicable.

Describe 'SPO-3.3 version-history control discriminates' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function Set-SPO {
            param($TenantSettingsSPO)
            Clear-TPState
            $data = @{ }
            if ($null -ne $TenantSettingsSPO) { $data['TenantSettingsSPO'] = $TenantSettingsSPO }
            Set-TPRawData -Key 'SharePoint' -Data ([pscustomobject]@{
                CollectorId = 'x'; CollectedAt = 'n'; Success = $true; Data = $data
            })
        }
        function State { (Get-TPFindings | Where-Object { $_.ControlId -eq 'SPO-3.3' } | Select-Object -First 1).State }
    }

    It 'Satisfied when automatic version trimming is the org default' {
        Set-SPO -TenantSettingsSPO @{ EnableAutoExpirationVersionTrim = $true; MajorVersionLimit = 0 }
        Test-TPControlSPOVersionHistory
        State | Should -Be 'Satisfied'
    }

    It 'Satisfied when a manual major-version limit is adequate (>= 100)' {
        Set-SPO -TenantSettingsSPO @{ EnableAutoExpirationVersionTrim = $false; MajorVersionLimit = 500 }
        Test-TPControlSPOVersionHistory
        State | Should -Be 'Satisfied'
    }

    It 'Gap when the manual limit is too low and auto-trim is off' {
        Set-SPO -TenantSettingsSPO @{ EnableAutoExpirationVersionTrim = $false; MajorVersionLimit = 10 }
        Test-TPControlSPOVersionHistory
        State | Should -Be 'Gap'
    }

    It 'NotApplicable when Get-SPOTenant data was not collected' {
        Set-SPO -TenantSettingsSPO $null
        Test-TPControlSPOVersionHistory
        State | Should -Be 'NotApplicable'
    }
}

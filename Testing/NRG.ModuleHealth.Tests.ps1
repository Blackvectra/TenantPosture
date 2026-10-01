#Requires -Version 7.0
#
# NRG.ModuleHealth.Tests.ps1
#
# Pins the MSAL assembly-conflict detector — the guard for the single most
# common M365-PowerShell failure (shared with ScubaGear). Uses -InstalledOverride
# to drive synthetic install states so the logic is verified without any real
# Graph / EXO modules present.

Describe 'Get-NRGModuleHealth' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function M { param([string]$Version, [string]$Base = 'C:\Program Files\PowerShell\Modules')
            [pscustomobject]@{ Version = [version]$Version; ModuleBase = $Base }
        }
    }

    It 'flags no conflict risk for a single clean version of each carrier' {
        $ov = @{
            'Microsoft.Graph.Authentication' = @( (M '2.15.0') )
            'ExchangeOnlineManagement'       = @( (M '3.2.0') )
            'MicrosoftTeams'                 = @( (M '5.8.0') )
        }
        $h = Get-NRGModuleHealth -InstalledOverride $ov
        $h.HasConflictRisk | Should -BeFalse
    }

    It 'flags conflict risk when a MSAL carrier has multiple versions installed' {
        $ov = @{
            'Microsoft.Graph.Authentication' = @( (M '2.15.0') )
            'ExchangeOnlineManagement'       = @( (M '3.4.0'), (M '3.2.0') )   # two versions
        }
        $h = Get-NRGModuleHealth -InstalledOverride $ov
        $h.HasConflictRisk | Should -BeTrue
        $exo = $h.Modules | Where-Object { $_.Name -eq 'ExchangeOnlineManagement' }
        $exo.MultipleVersions | Should -BeTrue
        $exo.Issues | Should -Contain 'multiple-versions'
        $exo.Newest | Should -Be '3.4.0'
    }

    It 'flags conflict risk when a MSAL carrier lives under a OneDrive path' {
        $ov = @{
            'Microsoft.Graph.Authentication' = @( (M '2.15.0' 'C:\Users\me\OneDrive\Documents\PowerShell\Modules\Microsoft.Graph.Authentication\2.15.0') )
            'ExchangeOnlineManagement'       = @( (M '3.2.0') )
        }
        $h = Get-NRGModuleHealth -InstalledOverride $ov
        $h.HasConflictRisk | Should -BeTrue
        $g = $h.Modules | Where-Object { $_.Name -eq 'Microsoft.Graph.Authentication' }
        $g.OneDrivePath | Should -BeTrue
        $g.Issues | Should -Contain 'onedrive-path'
    }

    It 'multiple versions of the non-carrier (Teams) does NOT trip the MSAL risk' {
        $ov = @{
            'Microsoft.Graph.Authentication' = @( (M '2.15.0') )
            'ExchangeOnlineManagement'       = @( (M '3.2.0') )
            'MicrosoftTeams'                 = @( (M '5.8.0'), (M '5.5.0') )
        }
        $h = Get-NRGModuleHealth -InstalledOverride $ov
        $h.HasConflictRisk | Should -BeFalse
        ($h.Modules | Where-Object { $_.Name -eq 'MicrosoftTeams' }).MultipleVersions | Should -BeTrue
    }

    It 'reports a missing module without throwing' {
        $ov = @{ 'ExchangeOnlineManagement' = @() }
        $h = Get-NRGModuleHealth -InstalledOverride $ov
        $exo = $h.Modules | Where-Object { $_.Name -eq 'ExchangeOnlineManagement' }
        $exo.Installed | Should -BeFalse
        $exo.Issues | Should -Contain 'missing'
    }

    It 'flags below-min versions, and pins nothing (EOM 3.7.2 floor, no pin)' {
        $ov = @{
            'Microsoft.Graph.Authentication' = @( (M '1.9.0') )   # below min 2.0.0
            'ExchangeOnlineManagement'       = @( (M '3.5.0') )   # below the 3.7.2 floor (no -DisableWAM yet)
        }
        $h = Get-NRGModuleHealth -InstalledOverride $ov
        ($h.Modules | Where-Object { $_.Name -eq 'Microsoft.Graph.Authentication' }).BelowMin | Should -BeTrue
        $exo = $h.Modules | Where-Object { $_.Name -eq 'ExchangeOnlineManagement' }
        $exo.BelowMin | Should -BeTrue
        $exo.OffPin   | Should -BeFalse -Because 'no version is pinned any more'
        $exo.RecommendedVersion | Should -BeNullOrEmpty
        $h2 = Get-NRGModuleHealth -InstalledOverride @{ 'ExchangeOnlineManagement' = @( (M '3.10.1') ) }
        ($h2.Modules | Where-Object { $_.Name -eq 'ExchangeOnlineManagement' }).Issues | Should -Not -Contain 'off-pin'
    }

    It 'never throws when called with no override (reads the real machine)' {
        { Get-NRGModuleHealth } | Should -Not -Throw
        (Get-NRGModuleHealth).PSObject | Should -Not -BeNullOrEmpty
    }
}

Describe 'A OneDrive online-only module file is named as the cause of a connect failure' {
    BeforeAll {
        $root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }
    It 'adds a hint for the exact message the first work-computer run produced' {
        $m = "The cloud file provider is not running. : 'C:\Users\op\OneDrive - Contoso\Documents\PowerShell\Modules\Microsoft.Graph.Reports\2.36.1\Microsoft.Graph.Reports.psd1'."
        $h = Get-NRGCloudFileHint -Message $m
        $h | Should -Match 'OneDrive'
        $h | Should -Match 'Always keep on this device'
        $h | Should -Match 'Install-NRGPrerequisites'
    }
    It 'says nothing for an unrelated connect error' {
        Get-NRGCloudFileHint -Message 'AADSTS50076: MFA required' | Should -BeNullOrEmpty
        Get-NRGCloudFileHint -Message '' | Should -BeNullOrEmpty
        Get-NRGCloudFileHint -Message $null | Should -BeNullOrEmpty
    }
}

Describe 'A MSAL version already loaded in the window is named as the cause, with the one fix that works' {
    BeforeAll {
        $root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }
    It 'recognizes the exact Graph error from the second work-computer run and says to open a NEW window' {
        $m = "InteractiveBrowserCredential authentication failed: Method not found: '!0 Microsoft.Identity.Client.BaseAbstractApplicationBuilder`1.WithLogging(Microsoft.IdentityModel.Abstractions.IIdentityLogger, Boolean)'."
        $h = Get-NRGMsalConflictHint -Message $m
        $h | Should -Match 'NEW PowerShell 7 window'
        $h | Should -Match 'already loaded'
    }
    It 'recognizes the assembly-load form and ignores unrelated errors' {
        Get-NRGMsalConflictHint -Message "Could not load file or assembly 'Microsoft.Identity.Client, Version=4.61.3.0'" | Should -Match 'NEW'
        Get-NRGMsalConflictHint -Message 'AADSTS50076: MFA required' | Should -BeNullOrEmpty
        Get-NRGMsalConflictHint -Message $null | Should -BeNullOrEmpty
    }
}

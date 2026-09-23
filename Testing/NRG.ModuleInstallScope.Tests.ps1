#Requires -Version 7.0
#
# NRG.ModuleInstallScope.Tests.ps1
#
# Pins Get-NRGModuleInstallScope — the decision Install-NRGPrerequisites.ps1
# and Invoke-NRGAssessment.ps1's own "Install/fix modules now?" prompt both
# now share, so a fresh module install never silently lands back inside a
# OneDrive-redirected Documents folder (the single most common cause of the
# MSAL assembly-conflict bug Get-NRGModuleHealth detects). Uses
# -UserModulePathOverride / -IsElevatedOverride to drive this deterministically
# — the real result would otherwise depend on whether the CI runner's own
# profile happens to be OneDrive-synced or elevated.

Describe 'Get-NRGModuleInstallScope' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }

    It 'stays CurrentUser when the module path is not OneDrive-synced' {
        $r = Get-NRGModuleInstallScope -UserModulePathOverride 'C:\Users\op\Documents\PowerShell\Modules' -IsElevatedOverride $false
        $r.Scope | Should -Be 'CurrentUser'
        $r.UserPathIsSynced | Should -BeFalse
        $r.StillSynced | Should -BeFalse
    }

    It 'switches to AllUsers when the synced path is caught in an elevated session' {
        $r = Get-NRGModuleInstallScope -UserModulePathOverride 'C:\Users\op\OneDrive - Contoso\Documents\PowerShell\Modules' -IsElevatedOverride $true
        $r.Scope | Should -Be 'AllUsers'
        $r.UserPathIsSynced | Should -BeTrue
        $r.StillSynced | Should -BeFalse -Because 'elevated means AllUsers is actually reachable, so the operator is not stuck'
    }

    It 'has no escape when the synced path is hit from a non-elevated session — StillSynced must be true' {
        # This is the exact shape of the bug: a fresh install answered Y to
        # "Install/fix modules now?" from an ordinary (non-admin) window with
        # OneDrive Known Folder Move active on Documents. Scope still has to
        # be CurrentUser here (AllUsers needs admin rights this session does
        # not have) — StillSynced is what tells the caller to warn instead of
        # silently reinstalling into the same OneDrive path.
        $r = Get-NRGModuleInstallScope -UserModulePathOverride 'C:\Users\op\OneDrive - Contoso\Documents\PowerShell\Modules' -IsElevatedOverride $false
        $r.Scope | Should -Be 'CurrentUser'
        $r.UserPathIsSynced | Should -BeTrue
        $r.StillSynced | Should -BeTrue
    }

    It 'matches on OneDrive anywhere in the path, case-insensitively' {
        $r = Get-NRGModuleInstallScope -UserModulePathOverride 'C:\Users\op\onedrive - contoso\Documents\PowerShell\Modules' -IsElevatedOverride $false
        $r.UserPathIsSynced | Should -BeTrue
    }

    It 'never installs, removes, or writes anything — pure decision only' {
        # Static guard: this function must stay side-effect-free so it is
        # safe to call from a read-only preflight, not just an installer.
        $content = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-NRGModuleInstallScope.ps1') -Raw
        $content | Should -Not -Match 'Install-PSResource|Uninstall-PSResource|Install-Module|Set-Content|Remove-Item' `
            -Because 'this function only decides a scope; callers install'
    }
}

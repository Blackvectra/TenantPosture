#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Pester coverage for Repair-NRGModuleHealth (Lib/Repair-NRGModuleHealth.ps1).

.DESCRIPTION
    Get-NRGModuleHealth detected the MSAL assembly conflict correctly and the
    preflight told operators to run Install-NRGPrerequisites.ps1 -- which only
    reconciled modules carrying a PinVersion. Microsoft.Graph.Authentication has
    no pin, so the installer inspected the NEWEST installed version, found it
    above the minimum, reported OK and left the duplicate in place. Detection was
    right; the named remedy was a no-op. These tests pin the repair that closes
    it, and in particular:

      - the exact real-world shape that produced a 10-minute silent hang
        (Microsoft.Graph.Authentication 2.38.0 + 2.37.0) is planned for repair;
      - the repair NEVER removes every version of a module;
      - it acts only on the MSAL carriers, never on a module whose duplicates are
        harmless;
      - it reports that an already-loaded assembly needs a new PowerShell
        session, because a repair that appears to do nothing gets reported as
        broken;
      - it is not wired into the assessment path, which must never uninstall
        software as a side effect of a read-only run.
#>

Describe 'Repair-NRGModuleHealth — duplicate MSAL carrier removal' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib/Get-NRGObjectField.ps1') -ErrorAction SilentlyContinue
        . (Join-Path $script:RepoRoot 'Lib/Get-NRGModuleHealth.ps1')
        . (Join-Path $script:RepoRoot 'Lib/Repair-NRGModuleHealth.ps1')

        function New-ModuleEntry {
            param([string] $Version, [string] $Base = 'C:\Program Files\WindowsPowerShell\Modules')
            [pscustomobject]@{ Version = [version]$Version; ModuleBase = $Base }
        }
    }

    Context 'the shape that actually hung a live run' {
        BeforeAll {
            # Exactly what the tenant run reported.
            $script:RealWorld = @{
                'Microsoft.Graph.Authentication' = @(
                    (New-ModuleEntry -Version '2.38.0'),
                    (New-ModuleEntry -Version '2.37.0')
                )
            }
        }

        It 'plans removal of the older Microsoft.Graph.Authentication' {
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $script:RealWorld
            $planned = @($r.Planned | Where-Object { $_.Name -eq 'Microsoft.Graph.Authentication' })
            @($planned).Count | Should -Be 1
            $planned[0].Version | Should -Be '2.37.0'
            $planned[0].Keeping | Should -Be '2.38.0'
        }

        It 'keeps the newest when the module carries no pin' {
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $script:RealWorld
            @($r.Planned | Where-Object { $_.Version -eq '2.38.0' }).Count | Should -Be 0 `
                -Because 'removing the newest would leave the operator worse off than the duplicate'
        }

        It 'changes nothing under -PlanOnly' {
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $script:RealWorld
            $r.Applied | Should -BeFalse
            @($r.Removed).Count | Should -Be 0
        }

        It 'changes nothing under -WhatIf' {
            $calls = [System.Collections.Generic.List[string]]::new()
            $r = Repair-NRGModuleHealth -InstalledOverride $script:RealWorld `
                -RemoveAction { param($n, $v) $calls.Add("$n $v") } -WhatIf
            $calls.Count | Should -Be 0 -Because '-WhatIf must not uninstall anything'
            $r.Applied | Should -BeFalse -Because 'a -WhatIf run removed nothing and must not report itself as applied'
            @($r.Removed).Count | Should -Be 0
        }

        It 'removes exactly the planned version when confirmed' {
            $calls = [System.Collections.Generic.List[string]]::new()
            $r = Repair-NRGModuleHealth -InstalledOverride $script:RealWorld `
                -RemoveAction { param($n, $v) $calls.Add("$n $v") } -Confirm:$false
            $calls.Count | Should -Be 1
            $calls[0] | Should -Be 'Microsoft.Graph.Authentication 2.37.0'
            @($r.Removed).Count | Should -Be 1
        }
    }

    Context 'it never removes every version' {
        It 'keeps the newest ExchangeOnlineManagement and removes the older duplicate' {
            # No version is pinned since the 3.7.2 floor: the newest survives.
            $state = @{
                'ExchangeOnlineManagement' = @(
                    (New-ModuleEntry -Version '3.9.0'),
                    (New-ModuleEntry -Version '3.7.2')
                )
            }
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $state
            $planned = @($r.Planned | Where-Object { $_.Name -eq 'ExchangeOnlineManagement' })
            @($planned).Count | Should -Be 1
            $planned[0].Version | Should -Be '3.7.2'
            $planned[0].Keeping | Should -Be '3.9.0'
        }

        It 'never removes the old 3.2.0 pin in favor of nothing: the newest still survives' {
            $state = @{
                'ExchangeOnlineManagement' = @(
                    (New-ModuleEntry -Version '3.4.0'),
                    (New-ModuleEntry -Version '3.2.0')
                )
            }
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $state
            $planned = @($r.Planned | Where-Object { $_.Name -eq 'ExchangeOnlineManagement' })
            $planned[0].Version | Should -Be '3.2.0'
            $planned[0].Keeping | Should -Be '3.4.0'
        }

        It 'always leaves at least one version of every module it touches' {
            $state = @{
                'Microsoft.Graph.Authentication' = @(
                    (New-ModuleEntry -Version '2.38.0'),
                    (New-ModuleEntry -Version '2.37.0'),
                    (New-ModuleEntry -Version '2.36.0')
                )
            }
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $state
            foreach ($name in $state.Keys) {
                # Count directly off the override. Group-Object on the planned
                # rows does NOT give the module name back reliably (they are
                # ordered dictionaries), and a missed lookup yields $null whose
                # @().Count is 1, not 0 -- which silently inverts this assertion.
                $installedCount = @($state[$name]).Count
                $plannedCount   = @($r.Planned | Where-Object { $_.Name -eq $name }).Count
                $plannedCount | Should -BeLessThan $installedCount `
                    -Because 'removing every version leaves the operator with no module at all'
            }
        }
    }

    Context 'it acts only on the MSAL carriers' {
        It 'ignores MicrosoftTeams duplicates' {
            # Teams does not bundle Microsoft.Identity.Client, so duplicates are
            # harmless. Get-NRGModuleHealth already refuses to flag them; the
            # repair must not remove them either.
            $state = @{
                'MicrosoftTeams' = @(
                    (New-ModuleEntry -Version '6.0.0'),
                    (New-ModuleEntry -Version '5.9.0')
                )
            }
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $state
            @($r.Planned).Count | Should -Be 0
        }

        It 'plans nothing on a clean single-version machine' {
            $state = @{
                'Microsoft.Graph.Authentication' = @((New-ModuleEntry -Version '2.38.0'))
                'ExchangeOnlineManagement'       = @((New-ModuleEntry -Version '3.2.0'))
            }
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride $state
            @($r.Planned).Count | Should -Be 0
        }
    }

    Context 'it is honest about what a removal does not do' {
        It 'declares a restart is required when MSAL is already loaded' {
            # Removing files on disk cannot unload an assembly already in this
            # process. An operator who repairs and immediately re-runs in the
            # same window sees the identical hang.
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride @{
                'Microsoft.Graph.Authentication' = @(
                    (New-ModuleEntry -Version '2.38.0'),
                    (New-ModuleEntry -Version '2.37.0')
                )
            }
            # Asserted against the result's OWN fields rather than the host's
            # real AppDomain. Branching on whether this particular test machine
            # happens to have MSAL loaded makes the test pass for the wrong
            # reason on one of the two paths and never exercises the other.
            $expected = (@($r.Planned).Count -gt 0 -and @($r.LoadedMsal).Count -gt 0)
            $r.RestartRequired | Should -Be $expected
        }

        It 'never claims a restart is needed when there is nothing to remove' {
            $r = Repair-NRGModuleHealth -PlanOnly -InstalledOverride @{
                'Microsoft.Graph.Authentication' = @((New-ModuleEntry -Version '2.38.0'))
            }
            @($r.Planned).Count | Should -Be 0
            $r.RestartRequired | Should -BeFalse `
                -Because 'a no-op repair must not send the operator to restart for nothing'
        }

        It 'records a failed removal instead of aborting the rest' {
            $state = @{
                'Microsoft.Graph.Authentication' = @(
                    (New-ModuleEntry -Version '2.38.0'),
                    (New-ModuleEntry -Version '2.37.0'),
                    (New-ModuleEntry -Version '2.36.0')
                )
            }
            $seen = [System.Collections.Generic.List[string]]::new()
            $r = Repair-NRGModuleHealth -InstalledOverride $state -Confirm:$false -RemoveAction {
                param($n, $v)
                $seen.Add($v)
                if ($v -eq '2.37.0') { throw 'file is locked by OneDrive' }
            }
            $seen.Count | Should -Be 2 -Because 'a locked version must not abort the remaining removals'
            @($r.Failed).Count | Should -Be 1
            $r.Failed[0].Version | Should -Be '2.37.0'
            @($r.Removed).Count | Should -Be 1
        }
    }

    Context 'it is not wired into the assessment path' {
        It 'no collector, evaluator or publisher calls it' {
            # A read-only assessment must never uninstall software as a side
            # effect of being run. The repair is operator-invoked only.
            $dirs = @('Collectors', 'Evaluators', 'Publishers') |
                ForEach-Object { Join-Path $script:RepoRoot $_ } |
                Where-Object { Test-Path -LiteralPath $_ }
            $hits = @()
            foreach ($d in $dirs) {
                $hits += @(Get-ChildItem -LiteralPath $d -Recurse -Filter *.ps1 -ErrorAction SilentlyContinue |
                    Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'Repair-NRGModuleHealth' } |
                    ForEach-Object { $_.FullName })
            }
            $hits | Should -BeNullOrEmpty
        }

        It 'Connect-NRGServices names it but does not invoke it' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Connect-NRGServices.ps1') -Raw
            $src | Should -Match 'Repair-NRGModuleHealth' `
                -Because 'the preflight must name a remedy that actually works'
            # It appears only inside the Write-Host advice string, never as a call.
            $src | Should -Not -Match '(?m)^\s*(\$\w+\s*=\s*)?Repair-NRGModuleHealth\b' `
                -Because 'connecting must not uninstall modules on its own'
        }

        It 'declares SupportsShouldProcess with ConfirmImpact High' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Repair-NRGModuleHealth.ps1') -Raw
            $src | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
            $src | Should -Match "ConfirmImpact\s*=\s*'High'"
        }

        It 'is exported from both the manifest and the module' {
            $psd1 = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')
            $psd1.FunctionsToExport | Should -Contain 'Repair-NRGModuleHealth'
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Raw) |
                Should -Match "'Repair-NRGModuleHealth'"
        }
    }
}

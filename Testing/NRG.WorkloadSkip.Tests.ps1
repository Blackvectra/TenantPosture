#Requires -Version 7.0
#
# NRG.WorkloadSkip.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purview was skipped unless -IncludePurview was given, because of a crash in
# ExchangeOnlineManagement 3.4.0 (2023); the batch runner never passed the
# switch, so every batch run silently skipped all 18 Purview controls. The
# module has had a supported -DisableWAM switch since 3.7.2. Purview is now
# on by default, the module floor is 3.7.2 with no pin, and a -Skip flag is
# recorded as coverage 'Skipped' so the report says "not assessed" instead
# of "data did not collect".

Describe 'Purview by default, -DisableWAM, and honest -Skip flags' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Entry   = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -Raw
        $script:Connect = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Connect-NRGServices.ps1') -Raw
        $script:Install = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Install-NRGPrerequisites.ps1') -Raw
        $script:Manifest = Import-PowerShellDataFile (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'Purview is assessed unless the operator skips it' {
        It 'the entry point no longer turns -SkipPurview on by default' {
            $script:Entry | Should -Not -Match '\$SkipPurview\s*=\s*\$true'
            $script:Entry | Should -Match '\[switch\] \$SkipPurview'
        }
        It 'keeps -IncludePurview so existing commands still run, and it decides nothing' {
            $script:Entry | Should -Match '\[switch\] \$IncludePurview'
            # The only remaining references are its declaration and comments.
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Entry, [ref]$tokens, [ref]$errs)
            $uses = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'IncludePurview' }, $true))
            $uses.Count | Should -Be 1 -Because 'the declaration is the only use'
        }
    }

    Context 'the Exchange sign-ins use the supported -DisableWAM switch' {
        It 'passes DisableWAM to Connect-ExchangeOnline (app-only and interactive) and Connect-IPPSSession when the module has it' {
            $script:Connect | Should -Match "ContainsKey\('DisableWAM'\)"
            ([regex]::Matches($script:Connect, "\['DisableWAM'\]\s*=\s*\`$true")).Count | Should -Be 3 -Because 'app-only EXO, interactive EXO and IPPS each get it'
        }
    }

    Context 'The Exchange module floor follows the PowerShell version (Get-NRGExoModuleFloor)' {
        # Microsoft's support table: 3.10.0+ needs 7.6; 3.5.0-3.9.2 need 7.4+.
        # The first live run had 3.9.2 beside PowerShell 7.6.6, accepted by a
        # minimum-only check, and Connect-ExchangeOnline failed inside the
        # module. The floor must rise with PowerShell, not only the ceiling fall.
        It 'PowerShell 7.6 requires 3.10.0 with no ceiling' {
            $f = Get-NRGExoModuleFloor -PSVersion ([version]'7.6.6') -PSHomePath 'C:\Program Files\PowerShell\7'
            $f.Min | Should -Be '3.10.0'; $f.Max | Should -BeNullOrEmpty; $f.Supported | Should -BeTrue; $f.StoreBuild | Should -BeFalse
        }
        It 'PowerShell 7.4 and 7.5 take 3.7.2 to 3.9.x' {
            foreach ($v in '7.4.6', '7.5.2') {
                $f = Get-NRGExoModuleFloor -PSVersion ([version]$v) -PSHomePath 'C:\Program Files\PowerShell\7'
                $f.Min | Should -Be '3.7.2'; $f.Max | Should -Be '3.9.99'; $f.Supported | Should -BeTrue
            }
        }
        It 'PowerShell 7.2 cannot run the floor at all and says to upgrade PowerShell' {
            $f = Get-NRGExoModuleFloor -PSVersion ([version]'7.2.24') -PSHomePath 'C:\Program Files\PowerShell\7'
            $f.Supported | Should -BeFalse; $f.Reason | Should -Match 'upgrade PowerShell'
        }
        It 'recognizes the Microsoft Store build by its WindowsApps home' {
            (Get-NRGExoModuleFloor -PSVersion ([version]'7.6.6') -PSHomePath 'C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe').StoreBuild | Should -BeTrue
            (Get-NRGExoModuleFloor -PSVersion ([version]'7.6.6') -PSHomePath 'C:\Program Files\PowerShell\7').StoreBuild | Should -BeFalse
        }
        It 'Get-NRGModuleHealth takes its Exchange minimum from the helper' {
            $health = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-NRGModuleHealth.ps1') -Raw
            $health | Should -Match 'Get-NRGExoModuleFloor'
        }
    }

    Context 'ExchangeOnlineManagement floor 3.7.2, no pin' {
        It 'the manifest, the entry point and the installer agree' {
            $exo = @($script:Manifest.RequiredModules | Where-Object { $_.ModuleName -eq 'ExchangeOnlineManagement' })[0]
            $exo.ModuleVersion | Should -Be '3.7.2'
            # The floor follows the PowerShell in use (Get-NRGExoModuleFloor); the
            # entry point and the installer must both take it from the helper.
            $script:Entry   | Should -Match "Name='ExchangeOnlineManagement';\s+MinVersion=\`$exoFloor\.Min;\s+PinVersion=\`$null"
            $script:Install | Should -Match "Name='ExchangeOnlineManagement';\s+MinVersion=\`$exoFloor\.Min;\s+PinVersion=\`$null"
            $script:Entry   | Should -Match 'Get-NRGExoModuleFloor'
            $script:Install | Should -Match 'Get-NRGExoModuleFloor'
            $script:Entry   | Should -Not -Match "PinVersion='3\.2\.0'"
            $script:Install | Should -Not -Match "PinVersion='3\.2\.0'"
        }
        It 'the installer takes the version range from the helper and installs by range' {
            $script:Install | Should -Match 'MaxVersion=\$exoFloor\.Max'
            $script:Install | Should -Match "Install-PSResource -Name \`$name -Version \`$range"
            $helper = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-NRGModuleInstallScope.ps1') -Raw
            $helper | Should -Match "\[version\]'7\.6\.0'"
            $helper | Should -Match "\[version\]'7\.4\.0'"
        }
    }

    Context 'a -Skip flag is recorded, so its controls read "not assessed"' {
        It 'Register-NRGCoverage accepts Skipped and Get-NRGCoverage returns it' {
            Clear-NRGState
            { Register-NRGCoverage -Family 'Purview' -Status 'Skipped' -Note 'Skipped for this run with -SkipPurview.' } | Should -Not -Throw
            $cov = Get-NRGCoverage
            $cov['Purview'].Status | Should -Be 'Skipped'
            $cov['Purview'].Note   | Should -Match '-SkipPurview'
            Clear-NRGState
        }
        It 'the entry point records every -Skip flag under the collector keys the controls depend on' {
            $controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls)
            $deps = @($controls | ForEach-Object { [string]$_.CollectorDependency -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
            foreach ($case in @(
                    @{ Flag = 'SkipPurview';       Keys = @('Purview') },
                    @{ Flag = 'SkipTeams';         Keys = @('Teams') },
                    @{ Flag = 'SkipSharePoint';    Keys = @('SharePoint') },
                    @{ Flag = 'SkipIntune';        Keys = @('Intune-EndpointSecurity', 'Intune-DeviceCompliance', 'Intune-AppProtection') },
                    @{ Flag = 'SkipPowerPlatform'; Keys = @('PowerPlatform') },
                    @{ Flag = 'SkipDNS';           Keys = @('DNS-EmailRecords') })) {
                $script:Entry | Should -Match ("On = \`$" + $case.Flag + ";")
                foreach ($k in $case.Keys) {
                    $deps | Should -Contain $k -Because "$k is a CollectorDependency in controls.json, so the scope classifier can match it"
                    $script:Entry | Should -Match ("'" + [regex]::Escape($k) + "'")
                }
            }
            $script:Entry | Should -Match "Register-NRGCoverage -Family \`$k -Status 'Skipped'"
        }
    }
}

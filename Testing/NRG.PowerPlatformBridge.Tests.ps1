#Requires -Version 7.0
#
# NRG.PowerPlatformBridge.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Power Platform (PPL-*) never collected. Microsoft documents
# Microsoft.PowerApps.Administration.PowerShell as .NET Framework / Windows
# PowerShell 5.x only, so it cannot run in this PowerShell 7 tool, and the
# fallback called Get-MgGraphAccessToken, which is not a Microsoft Graph
# PowerShell cmdlet. The collector now runs the module in a Windows
# PowerShell 5.1 child process pinned to the Graph tenant. The child itself
# can only be exercised on Windows against a real tenant; these tests pin
# everything around it: the mapping of its output, every failure reason, the
# tenant pin, and that the child stays read-only and EDR-quiet.

Describe 'Power Platform Windows PowerShell bridge' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/PowerPlatform/Invoke-NRGCollectPowerPlatform.ps1') -Raw
        $script:RealBridge = & $script:Mod { ${function:Invoke-NRGPowerPlatformBridge} }

        # Stand-ins inside MODULE scope, where the collector resolves them.
        # The bridge stand-in records the tenant it was asked for and returns
        # whatever the test put in $script:BridgeResult.
        & $script:Mod {
            Set-Item -Path 'function:script:Get-MgContext' -Value {
                if ($script:NoGraph) { return $null }
                [pscustomobject]@{ TenantId = '375e7ed2-25cc-4bec-bc68-890dc9095311' }
            }
            Set-Item -Path 'function:script:Invoke-NRGPowerPlatformBridge' -Value {
                param([string] $TenantId)
                $script:BridgeTenant = $TenantId
                $script:BridgeResult
            }
        }
        function script:Invoke-Collector([object]$BridgeResult, [bool]$NoGraph = $false) {
            & $script:Mod { param($r, $ng) $script:BridgeResult = $r; $script:NoGraph = $ng; $script:BridgeTenant = $null; Clear-NRGState } $BridgeResult $NoGraph
            Invoke-NRGCollectPowerPlatform 6>$null 3>$null
        }
        # What ConvertFrom-Json gives back for the child's output.
        function script:New-RanResult {
            '{"State":"Ran","Errors":[],
              "Environments":[{"EnvironmentName":"Default-375e","DisplayName":"Contoso (default)","EnvironmentType":"Default","Location":"unitedstates","CommonDataServiceDatabaseProvisioningState":"Succeeded"}],
              "DlpPolicies":[{"PolicyName":"p1","DisplayName":"Tenant DLP","EnvironmentType":"AllEnvironments",
                  "connectorGroups":[{"classification":"Confidential","connectors":[{"id":"shared_office365"}]},
                                     {"classification":"Blocked","connectors":[{"id":"shared_twitter"}]}]}],
              "TenantIsolation":{"properties":{"isDisabled":false,"rules":[]}},
              "TenantSettings":{"powerPlatform":{"governance":{"disableEnvironmentCreationByNonAdminUsers":true}}}}' | ConvertFrom-Json
        }
    }

    AfterAll {
        & $script:Mod { param($b)
            Remove-Item -Path 'function:script:Get-MgContext' -ErrorAction SilentlyContinue
            Set-Item -Path 'function:script:Invoke-NRGPowerPlatformBridge' -Value $b
        } $script:RealBridge
    }

    It 'maps a successful bridge run into the collector shape the evaluators read' {
        $r = Invoke-Collector (New-RanResult)
        $r.Success                              | Should -BeTrue
        $r.Data.Source                          | Should -Be 'module-winps'
        $r.Data.SectionStatus.Environments      | Should -Be 'Collected'
        $r.Data.Environments[0].Type            | Should -Be 'Default'
        $r.Data.DLPAvailable                    | Should -BeTrue
        @($r.Data.DLPPolicies[0].BusinessConnectors).Count | Should -Be 1
        @($r.Data.DLPPolicies[0].BlockedConnectors).Count  | Should -Be 1
        $r.Data.TenantIsolation.IsDisabled      | Should -BeFalse
        $r.Data.TenantGovernance.EnvironmentCreationRestricted | Should -BeTrue
        $r.Data.SectionStatus.TenantGovernance  | Should -Be 'Collected'
    }

    It 'pins the bridge sign-in to the Graph tenant' {
        Invoke-Collector (New-RanResult) | Out-Null
        (& $script:Mod { $script:BridgeTenant }) | Should -Be '375e7ed2-25cc-4bec-bc68-890dc9095311'
    }

    It 'does not run the bridge without a Graph tenant to pin it to' {
        $r = Invoke-Collector (New-RanResult) -NoGraph $true
        (& $script:Mod { $script:BridgeTenant }) | Should -BeNullOrEmpty
        $r.Success | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'no Graph tenant context'
    }

    It 'says exactly what to install when the module is missing from Windows PowerShell' {
        $r = Invoke-Collector ([pscustomobject]@{ State = 'NoModule' })
        $r.Success | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'not installed for Windows PowerShell 5\.1'
        ($r.Errors -join ' ') | Should -Match 'Install-Module Microsoft\.PowerApps\.Administration\.PowerShell'
    }

    It 'reports a failed Power Platform sign-in with its reason' {
        $r = Invoke-Collector ([pscustomobject]@{ State = 'SignInFailed'; Error = 'AADSTS50076' })
        $r.Success | Should -BeFalse
        ($r.Errors -join ' ') | Should -Match 'sign-in failed: AADSTS50076'
    }

    It 'explains the platform limit off Windows' {
        $r = Invoke-Collector ([pscustomobject]@{ State = 'NotWindows' })
        ($r.Errors -join ' ') | Should -Match 'only in Windows PowerShell 5\.1'
    }

    It 'a run that returned nothing is a failure, never an empty compliant tenant' {
        $r = Invoke-Collector ([pscustomobject]@{ State = 'Ran'; Errors = @('Get-AdminPowerAppEnvironment failed: 403') })
        $r.Success | Should -BeFalse
        $r.Data.SectionStatus.Environments | Should -Be 'NotRun'
        ($r.Errors -join ' ') | Should -Match '403'
    }

    It 'the real bridge returns NotWindows off Windows instead of trying to start powershell.exe' -Skip:$IsWindows {
        (& $script:RealBridge -TenantId '375e7ed2-25cc-4bec-bc68-890dc9095311').State | Should -Be 'NotWindows'
    }

    It 'the child script is read-only, tenant-pinned and not an encoded command' {
        $child = [regex]::Match($script:Src, "(?s)\`$child = @'(.*?)'@").Groups[1].Value
        $child | Should -Not -BeNullOrEmpty
        $child | Should -Match 'Add-PowerAppsAccount -Endpoint prod -TenantID \$TenantId'
        $child | Should -Match 'Get-PowerAppTenantIsolationPolicy -TenantId \$TenantId'
        # Add-PowerAppsAccount is the sign-in; every other module cmdlet must be a Get.
        $verbs = [regex]::Matches(($child -replace 'Add-PowerAppsAccount', ''), '\b([A-Z][a-z]+)-(Admin|Dlp|PowerApp|Tenant)\w*') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        $verbs | Should -Be @('Get')
        $script:Src | Should -Not -Match '-EncodedCommand\s+\$'
        $script:Src | Should -Not -Match 'Get-MgGraphAccessToken\s+-'
    }
}

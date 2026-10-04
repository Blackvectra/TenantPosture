#Requires -Version 7.0
#
# NRG.PowerPlatformApi.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Power Platform (PPL-*) never collected. Microsoft documents
# Microsoft.PowerApps.Administration.PowerShell as .NET Framework / Windows
# PowerShell 5.x only, so it cannot load in this PowerShell 7 tool; the
# fallback called Get-MgGraphAccessToken, which is not a Microsoft Graph
# PowerShell cmdlet; and running the module in a powershell.exe child is
# blocked by an ASR rule on the workstations this runs on. The collector now
# signs in to the Power Platform admin API in-process (MSAL, system browser,
# the same flow Connect-MgGraph uses) and calls its REST endpoints.
#
# The interactive sign-in itself can only run on a real workstation. These
# tests pin everything around it: section mapping, every failure reason, the
# tenant pin, that nothing spawns a process, and the evaluator fixes that
# collecting tenant settings exposed (PPL-2.2 / PPL-2.3 read absent settings
# through a $false default and scored Partial on every tenant).

Describe 'Power Platform admin API collector' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/PowerPlatform/Invoke-NRGCollectPowerPlatform.ps1') -Raw
        $script:RealToken = & $script:Mod { ${function:Get-NRGPowerPlatformToken} }
        $script:RealApi   = & $script:Mod { ${function:Invoke-NRGPowerPlatformApi} }

        # Stand-ins in MODULE scope, where the collector resolves them.
        & $script:Mod {
            Set-Item -Path 'function:script:Get-MgContext' -Value {
                if ($script:T_NoGraph) { return $null }
                [pscustomobject]@{ TenantId = 'abcdef01-2345-4678-9abc-def012345678'; Account = 'op@contoso.com'; AuthType = $script:T_AuthType }
            }
            Set-Item -Path 'function:script:Get-NRGPowerPlatformToken' -Value {
                param([string] $TenantId, [string] $LoginHint)
                $script:T_TokenTenant = $TenantId
                if ($script:T_TokenFails) { throw 'AADSTS50076: MFA required' }
                'fake-token'
            }
            Set-Item -Path 'function:script:Invoke-NRGPowerPlatformApi' -Value {
                param([string] $Uri, [string] $Token, [string] $Method = 'GET', [switch] $Paged)
                $script:T_Calls += "$Method $Uri"
                foreach ($k in $script:T_Fail) { if ($Uri -match $k) { throw "403 Forbidden ($k)" } }
                if ($Uri -match '/environments') { return @($script:T_Envs) }
                if ($Uri -match '/v2/policies')  { return @($script:T_Dlp) }
                if ($Uri -match 'tenantIsolationPolicy') { return ('{"properties":{"isDisabled":false,"allowedTenants":[{"tenantId":"x"}]}}' | ConvertFrom-Json) }
                if ($Uri -match 'listtenantsettings')    { return $script:T_Settings }
            }
        }

        function script:Invoke-Collector {
            param([hashtable] $Scenario = @{})
            & $script:Mod { param($s)
                Clear-NRGState
                $script:T_NoGraph     = [bool]$s['NoGraph']
                $script:T_AuthType    = if ($s['AuthType']) { $s['AuthType'] } else { 'Delegated' }
                $script:T_TokenFails  = [bool]$s['TokenFails']
                $script:T_Fail        = @($s['Fail'] | Where-Object { $_ })
                $script:T_Calls       = @()
                $script:T_TokenTenant = $null
                $script:T_Envs = if ($s.ContainsKey('Envs')) { $s['Envs'] } else {
                    @('{"name":"Default-375e","location":"unitedstates","properties":{"displayName":"Contoso (default)","environmentSku":"Default","states":{"management":{"id":"Ready"}}}}' | ConvertFrom-Json) }
                $script:T_Dlp = if ($s.ContainsKey('Dlp')) { $s['Dlp'] } else {
                    @('{"name":"p1","displayName":"Tenant DLP","environmentType":"AllEnvironments","connectorGroups":[{"classification":"Confidential","connectors":[{"id":"shared_office365"}]},{"classification":"Blocked","connectors":[{"id":"shared_twitter"}]}]}' | ConvertFrom-Json) }
                $script:T_Settings = if ($s.ContainsKey('Settings')) { $s['Settings'] } else {
                    ('{"disableEnvironmentCreationByNonAdminUsers":true,"disableTrialEnvironmentCreationByNonAdminUsers":false,"disablePortalsCreationByNonAdminUsers":true,"powerPlatform":{"powerApps":{"enableGuestsToMake":false}}}' | ConvertFrom-Json) }
            } $Scenario
            Invoke-NRGCollectPowerPlatform
        }
        function script:Get-Calls { & $script:Mod { $script:T_Calls } }
        function script:Get-Verdict([string]$Fn, [string]$Cid) {
            & $Fn | Out-Null
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0]
        }
    }

    AfterAll {
        & $script:Mod { param($t, $a)
            Remove-Item -Path 'function:script:Get-MgContext' -ErrorAction SilentlyContinue
            Set-Item -Path 'function:script:Get-NRGPowerPlatformToken' -Value $t
            Set-Item -Path 'function:script:Invoke-NRGPowerPlatformApi' -Value $a
        } $script:RealToken $script:RealApi
    }

    Context 'collection' {

        It 'maps every section into the shape the evaluators read' {
            $r = Invoke-Collector
            $r.Success | Should -BeTrue
            $r.Data.Source | Should -Be 'bap-api'
            foreach ($sec in 'Environments', 'DLPPolicies', 'TenantIsolation', 'TenantSettings', 'TenantGovernance') {
                $r.Data.SectionStatus[$sec] | Should -Be 'Collected' -Because $sec
            }
            $r.Data.Environments[0].Type | Should -Be 'Default'
            $r.Data.DLPAvailable | Should -BeTrue
            @($r.Data.DLPPolicies[0].BusinessConnectors).Count | Should -Be 1
            @($r.Data.DLPPolicies[0].BlockedConnectors).Count  | Should -Be 1
            $r.Data.TenantIsolation.IsDisabled | Should -BeFalse
            $r.Data.TenantGovernance.EnvironmentCreationRestricted      | Should -BeTrue
            $r.Data.TenantGovernance.TrialEnvironmentCreationRestricted | Should -BeFalse
            $r.Data.TenantSettings['DisablePortalsCreationByNonAdminUsers'] | Should -BeTrue
        }

        It 'reads the lower-case "...NonAdminusers" spelling from Microsoft''s definitions table too' {
            $r = Invoke-Collector @{ Settings = ('{"disableEnvironmentCreationByNonAdminusers":true,"disablePortalsCreationByNonAdminusers":false}' | ConvertFrom-Json) }
            $r.Data.TenantGovernance.EnvironmentCreationRestricted | Should -BeTrue
            $r.Data.TenantSettings['DisablePortalsCreationByNonAdminUsers'] | Should -BeFalse
        }

        It 'a setting the API did not return stays absent, never defaulted' {
            $r = Invoke-Collector @{ Settings = ('{}' | ConvertFrom-Json) }
            $r.Data.TenantSettings.Contains('DisablePortalsCreationByNonAdminUsers') | Should -BeFalse
            $r.Data.TenantGovernance.EnvironmentCreationRestricted | Should -BeNullOrEmpty
        }

        It 'pins the Power Platform sign-in to the Graph tenant' {
            Invoke-Collector | Out-Null
            (& $script:Mod { $script:T_TokenTenant }) | Should -Be 'abcdef01-2345-4678-9abc-def012345678'
        }

        It 'zero DLP policies is collected (a real Gap), not "not available"' {
            $r = Invoke-Collector @{ Dlp = @() }
            $r.Data.DLPAvailable | Should -BeTrue
            $r.Data.SectionStatus.DLPPolicies | Should -Be 'Collected'
            (Get-Verdict 'Test-NRGControlPowerPlatform' 'PPL-1.2').State | Should -Be 'Gap'
        }

        It 'a failed section is Failed with its reason, and the others still collect' {
            $r = Invoke-Collector @{ Fail = @('/environments') }
            $r.Success | Should -BeTrue
            $r.Data.SectionStatus.Environments | Should -Be 'Failed'
            $r.Data.SectionStatus.DLPPolicies  | Should -Be 'Collected'
            ($r.Errors -join ' ') | Should -Match 'environments query failed: 403'
        }

        It 'PPL-1.1 scores tenant isolation, and a failed isolation read is not assessed' {
            $null = Invoke-Collector @{ Fail = @('tenantIsolationPolicy') }
            (Get-Verdict 'Test-NRGControlPowerPlatform' 'PPL-1.1').State | Should -Be 'NotApplicable' -Because 'a failed read is not "isolation off"'
        }

        It 'every section failing is a failure that suggests the missing admin role' {
            $r = Invoke-Collector @{ Fail = @('.') }
            $r.Success | Should -BeFalse
            ($r.Errors -join ' ') | Should -Match 'Power Platform Administrator'
        }

        It 'a failed sign-in stops before any API call and says why' {
            $r = Invoke-Collector @{ TokenFails = $true }
            $r.Success | Should -BeFalse
            @(Get-Calls) | Should -BeNullOrEmpty
            ($r.Errors -join ' ') | Should -Match 'sign-in to the Power Platform admin API failed: AADSTS50076'
        }

        It 'app-only runs do not attempt the interactive sign-in' {
            $r = Invoke-Collector @{ AuthType = 'AppOnly' }
            (& $script:Mod { $script:T_TokenTenant }) | Should -BeNullOrEmpty
            ($r.Errors -join ' ') | Should -Match 'app-only'
        }

        It 'no Graph context, no sign-in' {
            $r = Invoke-Collector @{ NoGraph = $true }
            (& $script:Mod { $script:T_TokenTenant }) | Should -BeNullOrEmpty
            ($r.Errors -join ' ') | Should -Match 'no Graph tenant context'
        }
    }

    Context 'the evaluators do not score what was not read' {

        It 'PPL-2.2: no documented guest-flow setting, so it requires manual verification rather than Partial' {
            Invoke-Collector | Out-Null
            $f = Get-Verdict 'Test-NRGControlPPLAutomate' 'PPL-2.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'requires manual verification'
        }

        It 'PPL-2.3 scores the real portal setting both ways, and not at all when absent' {
            Invoke-Collector @{ Settings = ('{"disablePortalsCreationByNonAdminUsers":true}' | ConvertFrom-Json) } | Out-Null
            (Get-Verdict 'Test-NRGControlPPLPowerApps' 'PPL-2.3').State | Should -Be 'Satisfied'
            Invoke-Collector @{ Settings = ('{"disablePortalsCreationByNonAdminUsers":false}' | ConvertFrom-Json) } | Out-Null
            (Get-Verdict 'Test-NRGControlPPLPowerApps' 'PPL-2.3').State | Should -Be 'Partial'
            Invoke-Collector @{ Settings = ('{}' | ConvertFrom-Json) } | Out-Null
            (Get-Verdict 'Test-NRGControlPPLPowerApps' 'PPL-2.3').State | Should -Be 'NotApplicable'
        }

        It 'PPL-1.3 scores from the documented tenant setting' {
            Invoke-Collector @{ Settings = ('{"disableEnvironmentCreationByNonAdminUsers":false}' | ConvertFrom-Json) } | Out-Null
            (Get-Verdict 'Test-NRGControlPowerPlatform' 'PPL-1.3').State | Should -Be 'Gap'
        }
    }

    Context 'no child process, API guarded' {

        It 'the collector starts no process of any kind' {
            $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Src, [ref]$null, [ref]$null)
            $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { "$($_.GetCommandName())" })
            $cmds | Should -Not -Contain 'Start-Process'
            $cmds | Should -Not -Contain 'Start-Job'
            $cmds | Should -Not -Contain 'Start-ThreadJob'
            $cmds | Where-Object { $_ -match '(?i)(powershell|pwsh|cmd)(\.exe)?$' } | Should -BeNullOrEmpty
            $script:Src | Should -Not -Match 'System\.Diagnostics\.Process'
            $script:Src | Should -Not -Match '-EncodedCommand\s'
        }

        It 'the API helper refuses any host but the Power Platform admin API' {
            { & $script:RealApi -Uri 'https://evil.example/x' -Token 't' } | Should -Throw
        }

        It 'the API helper follows nextLink across pages' {
            & $script:Mod {
                $script:T_Page = 0
                Set-Item -Path 'function:script:Invoke-RestMethod' -Value {
                    param($Method, $Uri, $Headers, $ContentType, $TimeoutSec, $ErrorAction)
                    $script:T_Page++
                    if ($script:T_Page -eq 1) { return [pscustomobject]@{ value = @(1, 2); nextLink = 'https://api.bap.microsoft.com/next' } }
                    [pscustomobject]@{ value = @(3) }
                }
            }
            try {
                $rows = & $script:Mod { param($api) & $api -Uri 'https://api.bap.microsoft.com/x' -Token 't' -Paged } $script:RealApi
                @($rows) | Should -Be @(1, 2, 3)
            } finally {
                & $script:Mod { Remove-Item -Path 'function:script:Invoke-RestMethod' -ErrorAction SilentlyContinue }
            }
        }

        It 'the token helper fails with a clear reason when it cannot sign in' {
            # No browser (CI) or no sign-in library: either way it must throw a
            # reason, never return an empty token.
            { & $script:Mod { param($t) & $t -TenantId 'abcdef01-2345-4678-9abc-def012345678' -TimeoutSeconds 5 } $script:RealToken } | Should -Throw
        }
    }
}

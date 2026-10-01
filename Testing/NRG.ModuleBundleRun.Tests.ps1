#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.ModuleBundleRun.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: End-to-end proof of the module bundle (.modules/). Runs the REAL entry points
             (Invoke-NRGAssessment.ps1, Invoke-NRGBatchAssessment.ps1) in fresh child
             processes against stand-in Microsoft Graph / Exchange / Teams modules, with TWO
             copies of every module on disk: the bundle's, and a "machine" copy at a HIGHER
             version on PSModulePath behind it. Every stand-in prints which copy it is when it
             is imported and when one of its commands runs, so the output says exactly which
             copy the tool used.
             Unit tests (NRG.ModuleBundle.Tests.ps1) prove the pieces; this proves the whole:
             that the bundle wins where it matters (the RequiredModules import done by the
             manifest, the explicit-path imports in Connect-NRGServices, command autoload in
             the batch runner, which calls Connect-MgGraph before it imports the tool), and
             that PSModulePath is back to what it was after the run.
    Invariants:
      - bundle present and valid: every Graph / Exchange / Teams copy imported or called is
        the bundle's, none is the higher-version machine copy
      - bundle absent: today's behavior, the machine copies are used, with no bundle message
      - bundle present but invalid: said so, not used, machine copies used (never half of each)
      - PSModulePath after the run equals PSModulePath before it, on a normal run and on an
        early exit
    Service boundary: stub modules only. Nothing touches a network or a tenant.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

BeforeDiscovery {
    # A real .modules/ in the repo (a workstation that built one) must not be what the
    # "no bundle" case measures, so that case is skipped there rather than made to lie.
    $script:RepoHasBundle = Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) '.modules')
}

Describe 'Module bundle: the real entry points against stubbed modules with a higher-version decoy on the machine' {

    BeforeAll {
        $script:Root = Split-Path -Parent $PSScriptRoot
        $script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-bundlerun-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Pwsh = [System.Environment]::ProcessPath
        $script:Sep  = [string][System.IO.Path]::PathSeparator

        . (Join-Path $script:Root 'Lib/Get-NRGModuleInstallScope.ps1')
        . (Join-Path $script:Root 'Lib/Get-NRGModuleBundle.ps1')
        . (Join-Path $script:Root 'Lib/New-NRGModuleBundle.ps1')
        $script:Floor = Get-NRGExoModuleFloor
        $script:Spec  = @(Get-NRGModuleBundleSpec -ToolRoot $script:Root)

        # What each stand-in defines. Every one prints a marker when it is imported, so which
        # copy loaded is in the output even if nothing calls it; the commands print their own.
        $script:StubBody = {
            param([string] $Name, [string] $Version, [string] $Tag)
            $mark = "Write-Host 'NRGSTUB-IMPORT $Name $Version $Tag'"
            $call = { param($cmd) "Write-Host 'NRGSTUB-CALL $Name $Version $Tag $cmd'" }
            switch ($Name) {
                'Microsoft.Graph.Authentication' {
                    @"
$mark
function Connect-MgGraph { [CmdletBinding()] param(`$Scopes, `$ContextScope, [switch] `$NoWelcome, `$TenantId, `$Environment, `$ClientId, `$CertificateThumbprint) $(& $call 'Connect-MgGraph') }
function Disconnect-MgGraph { [CmdletBinding()] param() }
function Get-MgContext { [pscustomobject]@{ Account = 'admin@smoke.example'; TenantId = '00000000-0000-0000-0000-00000000abcd'; Scopes = @(); Environment = 'Global' } }
function Invoke-MgGraphRequest { [CmdletBinding()] param(`$Uri, `$Method, `$OutputType, `$Headers, `$Body) @{ value = @() } }
"@
                }
                'ExchangeOnlineManagement' {
                    @"
$mark
function Connect-ExchangeOnline { [CmdletBinding()] param([switch] `$ShowBanner, [switch] `$DisableWAM, `$Organization, `$UserPrincipalName, `$DelegatedOrganization, [switch] `$SkipLoadingFormatData) $(& $call 'Connect-ExchangeOnline') }
function Disconnect-ExchangeOnline { [CmdletBinding()] param(`$Confirm) }
function Get-ConnectionInformation { @() }
"@
                }
                'MicrosoftTeams' {
                    @"
$mark
function Connect-MicrosoftTeams { [CmdletBinding()] param(`$TenantId) $(& $call 'Connect-MicrosoftTeams') }
function Get-CsTenant { [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-00000000abcd' } }
"@
                }
                default { $mark }
            }
        }

        # One stand-in module on disk: <Base>\<Name>\<Version>\<Name>.psd1 + .psm1
        $script:WriteStub = {
            param([string] $Base, [string] $Name, [string] $Version, [string] $Tag)
            $dir = Join-Path (Join-Path $Base $Name) $Version
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir "$Name.psd1") -Encoding utf8 -Value "@{ RootModule = '$Name.psm1'; ModuleVersion = '$Version'; GUID = '$([guid]::NewGuid())'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
            Set-Content -LiteralPath (Join-Path $dir "$Name.psm1") -Encoding utf8 -Value (& $script:StubBody $Name $Version $Tag)
        }

        # The bundle is built by the REAL builder; only the download is replaced.
        $script:BuildBundle = {
            param([string] $Path)
            $save = {
                param($Name, $Request, $Path)
                $version = if ($Request -match '^[\[(]') { $script:Floor['Min'] } else { $Request }
                & $script:WriteStub $Path $Name $version 'bundle'
            }
            $r = New-NRGModuleBundle -ToolRoot $script:Root -Path $Path -SaveAction $save -Confirm:$false 6>$null
            if (-not $r['Valid']) { throw "stub bundle did not validate: $($r['Errors'] -join '; ')" }
        }

        # The machine's own modules: same names, HIGHER versions than the bundle's, so a
        # "newest copy wins" rule picks them.
        $script:Machine = Join-Path $script:Tmp 'machine'
        foreach ($m in $script:Spec) {
            if ($m['Optional']) { continue }
            $v = if ($m['Name'] -eq 'ExchangeOnlineManagement') {
                if ($script:Floor['Max']) { $script:Floor['Max'] } else { ([version]$script:Floor['Min']).Major.ToString() + '.' + ([version]$script:Floor['Min']).Minor + '.50' }
            } elseif ($m['Family'] -eq 'Graph') { '2.99.0' } else { '8.5.0' }
            & $script:WriteStub $script:Machine $m['Name'] $v 'decoy'
        }
        $script:Bundle = Join-Path $script:Tmp 'bundle'
        & $script:BuildBundle $script:Bundle

        # Runs one entry point in a fresh pwsh. The driver puts the machine copies on PSModulePath
        # (the way a real machine has them), optionally points NRG_MODULE_BUNDLE at a bundle,
        # and reports PSModulePath before and after the script.
        $script:Run = {
            param([string] $ScriptName, [string] $ArgText, [string] $BundlePath, [string] $Prelude = '')
            $driver = Join-Path $script:Tmp ("driver-" + [guid]::NewGuid().ToString('N') + '.ps1')
            $bundleLine = if ($BundlePath) { "`$env:NRG_MODULE_BUNDLE = '$BundlePath'" } else { "Remove-Item Env:NRG_MODULE_BUNDLE -ErrorAction SilentlyContinue" }
            Set-Content -LiteralPath $driver -Encoding utf8 -Value @"
`$env:PSModulePath = '$($script:Machine)' + '$($script:Sep)' + `$env:PSModulePath
$bundleLine
$Prelude
`$before = `$env:PSModulePath
& '$(Join-Path $script:Root $ScriptName)' $ArgText
`$code = `$LASTEXITCODE
Write-Output "NRGTEST-PSMP-BEFORE=`$before"
Write-Output "NRGTEST-PSMP-AFTER=`$env:PSModulePath"
exit `$code
"@
            $text = (& $script:Pwsh -NoProfile -NonInteractive -File $driver *>&1 | Out-String)
            $code = $LASTEXITCODE
            Remove-Item -LiteralPath $driver -Force -ErrorAction SilentlyContinue
            $clean = $text -replace "\e\[[0-9;]*m", ''
            [pscustomobject]@{
                Output   = $clean
                ExitCode = $code
                Before   = ([regex]::Match($clean, '(?m)^NRGTEST-PSMP-BEFORE=(.*)$').Groups[1].Value).TrimEnd()
                After    = ([regex]::Match($clean, '(?m)^NRGTEST-PSMP-AFTER=(.*)$').Groups[1].Value).TrimEnd()
            }
        }
        $script:Skips = '-NonInteractive -SkipPurview -SkipSharePoint -SkipIntune -SkipPowerPlatform -SkipDNS'
        $script:StubLines = { param($Text) @([regex]::Matches($Text, '(?m)^NRGSTUB-(IMPORT|CALL) (\S+) (\S+) (\S+)') | ForEach-Object { [pscustomobject]@{ Kind = $_.Groups[1].Value; Module = $_.Groups[2].Value; Version = $_.Groups[3].Value; Tag = $_.Groups[4].Value } }) }
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Invoke-NRGAssessment.ps1 with a valid bundle' {
        BeforeAll {
            $out = Join-Path $script:Tmp 'assess-bundle'
            $script:A = & $script:Run 'Invoke-NRGAssessment.ps1' "$script:Skips -OutputPath '$out'" $script:Bundle
            $script:AStubs = & $script:StubLines $script:A.Output
        }

        It 'reports the bundle it is using' {
            $script:A.Output | Should -Match '\[\+\] Module bundle: .*\(\d+ modules, one version each\)' -Because $script:A.Output
        }
        It 'imports Graph, Exchange and Teams, and every copy it imports is the bundle''s' {
            foreach ($name in 'Microsoft.Graph.Authentication', 'ExchangeOnlineManagement', 'MicrosoftTeams') {
                @($script:AStubs | Where-Object { $_.Kind -eq 'IMPORT' -and $_.Module -eq $name }).Count |
                    Should -BeGreaterThan 0 -Because "$name was never imported:`n$($script:A.Output)"
            }
            @($script:AStubs | Where-Object { $_.Tag -eq 'decoy' }) | Should -BeNullOrEmpty -Because 'a machine copy with a higher version was imported or called'
        }
        It 'the commands that ran came from the bundle (Connect-MgGraph, Connect-ExchangeOnline, Connect-MicrosoftTeams)' {
            foreach ($name in 'Microsoft.Graph.Authentication', 'ExchangeOnlineManagement', 'MicrosoftTeams') {
                @($script:AStubs | Where-Object { $_.Kind -eq 'CALL' -and $_.Module -eq $name -and $_.Tag -eq 'bundle' }).Count |
                    Should -BeGreaterThan 0 -Because "no command from the bundle's $name ran:`n$($script:A.Output)"
            }
        }
        It 'imports the Graph submodules the connect step pre-imports from the bundle only' {
            foreach ($name in 'Microsoft.Graph.Reports', 'Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Users') {
                $hits = @($script:AStubs | Where-Object { $_.Kind -eq 'IMPORT' -and $_.Module -eq $name })
                $hits.Count | Should -BeGreaterThan 0 -Because "$name was not pre-imported"
                @($hits | Where-Object { $_.Tag -ne 'bundle' }) | Should -BeNullOrEmpty
            }
        }
        It 'loaded the pinned versions' {
            # (@(...)[0] of a lone ordered dictionary is its first VALUE, so pick the entry first.)
            $authPin = [string](@($script:Spec | Where-Object { $_['Name'] -eq 'Microsoft.Graph.Authentication' })[0]['Version'])
            # What the planner asks for: the preferred pin when this PowerShell allows it, else the
            # range (the stub then saves the floor minimum, as $script:BuildBundle does).
            $exoReq  = [string](@(Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor | Where-Object { $_['Name'] -eq 'ExchangeOnlineManagement' })[0]['Request'])
            $exoPin  = if ($exoReq -match '^[\[(]') { [string]$script:Floor['Min'] } else { $exoReq }
            @($script:AStubs | Where-Object { $_.Module -eq 'Microsoft.Graph.Authentication' } | ForEach-Object { $_.Version } | Sort-Object -Unique) | Should -Be @($authPin)
            @($script:AStubs | Where-Object { $_.Module -eq 'ExchangeOnlineManagement' } | ForEach-Object { $_.Version } | Sort-Object -Unique) | Should -Be @($exoPin)
        }
        It 'puts PSModulePath back exactly as it was' {
            $script:A.Before | Should -Not -BeNullOrEmpty
            $script:A.After  | Should -Be $script:A.Before
        }
        It 'did not stop at the module prerequisite check (the bundle satisfies it, so there is no install prompt)' {
            $script:A.Output | Should -Not -Match 'Missing: ' -Because $script:A.Output
            $script:A.Output | Should -Not -Match 'Install/fix modules now'
        }
    }

    Context 'Invoke-NRGAssessment.ps1 exits early after the bundle is active' {
        It 'restores PSModulePath on an early exit, not only when the run finishes' {
            # -RegisterApp without -TenantDomain exits 1 right after the module import.
            $r = & $script:Run 'Invoke-NRGAssessment.ps1' '-RegisterApp' $script:Bundle
            $r.ExitCode | Should -Be 1 -Because $r.Output
            $r.Output | Should -Match 'NRGSTUB-IMPORT Microsoft.Graph.Authentication \S+ bundle' -Because 'the early exit must be one that happens with the bundle active'
            $r.After | Should -Be $r.Before
        }
    }

    Context 'Invoke-NRGBatchAssessment.ps1, which calls Connect-MgGraph before it imports the tool' {
        BeforeAll {
            $clients = Join-Path $script:Tmp 'clients.json'
            Set-Content -LiteralPath $clients -Encoding utf8 -Value (@{ clients = @(@{
                        ClientName = 'Smoke'; TenantDomain = 'smoke.example'; TenantId = '11111111-1111-4111-8111-111111111111'
                        DelegatedOrg = 'smoke.onmicrosoft.com'; DnsDomains = @(); SkipPurview = $true; SkipTeams = $true
                        SkipSharePoint = $true; SkipIntune = $true; SkipPowerPlatform = $true; SkipDNS = $true; Notes = ''; Active = $true
                    }) } | ConvertTo-Json -Depth 5)
            $out = Join-Path $script:Tmp 'batch-out'
            # The stub context reports a different tenant, so the runner skips the client
            # after switching context: enough to prove which Graph module it called.
            $script:B = & $script:Run 'Invoke-NRGBatchAssessment.ps1' "-ClientsFile '$clients' -OutputRoot '$out' -OnlyClient smoke.example" $script:Bundle
            $script:BStubs = & $script:StubLines $script:B.Output
        }

        It 'authenticates with the bundle''s Microsoft.Graph.Authentication (command autoload, before the tool is imported)' {
            @($script:BStubs | Where-Object { $_.Kind -eq 'CALL' -and $_.Module -eq 'Microsoft.Graph.Authentication' -and $_.Tag -eq 'bundle' }).Count |
                Should -BeGreaterThan 0 -Because $script:B.Output
            @($script:BStubs | Where-Object { $_.Tag -eq 'decoy' }) | Should -BeNullOrEmpty -Because $script:B.Output
        }
        It 'puts PSModulePath back exactly as it was' {
            $script:B.After | Should -Be $script:B.Before
        }
    }

    Context 'a machine copy is already loaded in the session before the tool starts' {
        It 'says the bundle cannot replace it and asks for a new window, instead of silently using the wrong copy' {
            $out = Join-Path $script:Tmp 'assess-preloaded'
            # The operator ran Connect-MgGraph (or a profile imported Graph) earlier in this window.
            $r = & $script:Run 'Invoke-NRGAssessment.ps1' "$script:Skips -OutputPath '$out'" $script:Bundle 'Import-Module Microsoft.Graph.Authentication'
            $r.Output | Should -Match 'already loaded' -Because $r.Output
            $r.Output | Should -Match 'new PowerShell window'
            $stubs = & $script:StubLines $r.Output
            @($stubs | Where-Object { $_.Module -eq 'Microsoft.Graph.Authentication' -and $_.Tag -eq 'decoy' -and $_.Kind -eq 'IMPORT' }).Count | Should -Be 1 -Because 'the machine copy was loaded first'
            @($stubs | Where-Object { $_.Module -eq 'Microsoft.Graph.Authentication' -and $_.Tag -eq 'bundle' }) | Should -BeNullOrEmpty -Because 'a loaded module is not swapped, and the output must not pretend otherwise'
            $r.After | Should -Be $r.Before
        }
    }

    Context 'no bundle' {
        It 'uses the machine copies and says nothing about a bundle' -Skip:$script:RepoHasBundle {
            $out = Join-Path $script:Tmp 'assess-nobundle'
            $r = & $script:Run 'Invoke-NRGAssessment.ps1' "$script:Skips -OutputPath '$out'" $null
            $stubs = & $script:StubLines $r.Output
            @($stubs | Where-Object { $_.Tag -eq 'decoy' -and $_.Module -eq 'Microsoft.Graph.Authentication' }).Count | Should -BeGreaterThan 0 -Because $r.Output
            @($stubs | Where-Object { $_.Tag -eq 'bundle' }) | Should -BeNullOrEmpty
            $r.Output | Should -Not -Match 'Module bundle'
            $r.After | Should -Be $r.Before
        }
        It 'warns when NRG_MODULE_BUNDLE points at a folder that does not exist, and uses the machine copies' {
            $out = Join-Path $script:Tmp 'assess-missing'
            $r = & $script:Run 'Invoke-NRGAssessment.ps1' "$script:Skips -OutputPath '$out'" (Join-Path $script:Tmp 'does-not-exist')
            $r.Output | Should -Match 'NRG_MODULE_BUNDLE is set to .* but that folder does not exist'
            @((& $script:StubLines $r.Output) | Where-Object { $_.Tag -eq 'bundle' }) | Should -BeNullOrEmpty
            $r.After | Should -Be $r.Before
        }
    }

    Context 'a bundle that is present but not valid' {
        It 'says why, does not use it, and does not mix its copies with the machine''s' {
            $broken = Join-Path $script:Tmp 'broken'
            & $script:BuildBundle $broken
            Remove-Item -LiteralPath (Join-Path $broken 'nrg-bundle.json') -Force   # the state an interrupted build leaves
            $out = Join-Path $script:Tmp 'assess-broken'
            $r = & $script:Run 'Invoke-NRGAssessment.ps1' "$script:Skips -OutputPath '$out'" $broken
            $r.Output | Should -Match 'was not used'
            $r.Output | Should -Match 'no-lock'
            $stubs = & $script:StubLines $r.Output
            @($stubs | Where-Object { $_.Tag -eq 'bundle' }) | Should -BeNullOrEmpty -Because 'a half-built bundle must not be partly used'
            @($stubs | Where-Object { $_.Tag -eq 'decoy' -and $_.Module -eq 'Microsoft.Graph.Authentication' }).Count | Should -BeGreaterThan 0
            $r.After | Should -Be $r.Before
        }
    }
}

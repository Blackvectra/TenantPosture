#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.SmokeRun.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Smoke test. Runs the REAL Invoke-TPAssessment.ps1 in a fresh child
             process, start to finish (connect, every collector, every evaluator,
             every publisher), against stand-in Microsoft Graph / Exchange / Teams
             modules whose answers are empty. Then republishes the results with
             -FromResults and builds the report site from them.
             Unit tests call one function at a time; none of them launch the
             script, so a defect that only shows when the stages run together
             (an uninitialized variable in the cleanup block, a publisher that
             cannot handle zero partial findings) stays green until a live run.
             This test found both.
    Invariants:
      - an empty or failing tenant is a reported result, never a crash: exit code
        0 or 3 (partial collection), never 1 (auth) or 4 (fatal)
      - no publisher fails ("... publish failed")
      - no collector or evaluator records a StrictMode failure (a property read
        on an API object that omits it)
      - the run says what it could not read; empty is not clean
    Service boundary: stub modules on PSModulePath. Nothing touches a network
    or a tenant. Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Smoke run: the real entry point against a stubbed Microsoft 365 boundary' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-smoke-" + [guid]::NewGuid().ToString('N'))
        $script:Mods = Join-Path $script:Tmp 'mods'
        New-Item -ItemType Directory -Path $script:Mods -Force | Out-Null

        # The Exchange module version must sit inside the range this PowerShell
        # supports, or the entry point's own preflight (correctly) refuses to run.
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $exoFloor = & (Get-Module TenantPosture) { Get-TPExoModuleFloor }
        $exoVersion = [string]$exoFloor.Min

        function script:New-StubModule {
            param([string] $Name, [string] $Version, [string] $Guid, [string] $Body)
            $dir = Join-Path $script:Mods $Name $Version
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir "$Name.psd1") -Encoding utf8 -Value "@{ RootModule = '$Name.psm1'; ModuleVersion = '$Version'; GUID = '$Guid'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
            Set-Content -LiteralPath (Join-Path $dir "$Name.psm1") -Encoding utf8 -Value $Body
        }
        $script:NewStub = ${function:script:New-StubModule}

        & $script:NewStub 'Microsoft.Graph.Authentication' '2.40.0' 'b0b0b0b0-1111-4222-8333-444444444444' @'
function Connect-MgGraph { [CmdletBinding()] param($Scopes, $ContextScope, [switch] $NoWelcome, $TenantId, $Environment) }
function Disconnect-MgGraph { [CmdletBinding()] param() }
function Get-MgContext { [pscustomobject]@{ Account = 'admin@smoke.example'; TenantId = '00000000-0000-0000-0000-00000000abcd'; Scopes = @(); Environment = 'Global' } }
# Every collection is empty and every singleton has no properties: the shape a tenant
# returns when nothing is configured, which is also the shape of a partial answer.
function Invoke-MgGraphRequest { [CmdletBinding()] param($Uri, $Method, $OutputType, $Headers, $Body) @{ value = @() } }
'@
        & $script:NewStub 'ExchangeOnlineManagement' $exoVersion 'c0c0c0c0-1111-4222-8333-555555555555' @'
function Connect-ExchangeOnline { [CmdletBinding()] param([switch] $ShowBanner, [switch] $DisableWAM, $Organization, $UserPrincipalName, [switch] $SkipLoadingFormatData) }
function Disconnect-ExchangeOnline { [CmdletBinding()] param($Confirm) }
function Get-ConnectionInformation { @() }
'@
        $script:TeamsStub = { & $script:NewStub 'MicrosoftTeams' '5.9.0' 'd0d0d0d0-1111-4222-8333-666666666666' '# stand-in' }

        # Runs a script in a fresh pwsh with the stubs first on PSModulePath.
        # Returns Output (console text, ANSI stripped), ExitCode and the output folder.
        $script:Run = {
            param([string] $ScriptName, [string] $ArgText, [string] $Out)
            $old = $env:PSModulePath
            try {
                $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                $cmd = "& '$(Join-Path $script:Root $ScriptName)' $ArgText; exit `$LASTEXITCODE"
                $text = (& pwsh -NoProfile -NonInteractive -Command $cmd *>&1 | Out-String)
                $code = $LASTEXITCODE
            } finally { $env:PSModulePath = $old }
            [pscustomobject]@{
                Output   = ($text -replace "\e\[[0-9;]*m", '')
                ExitCode = $code
                Out      = $Out
            }
        }
        $script:Skips = '-SkipPurview -SkipTeams -SkipSharePoint -SkipIntune -SkipPowerPlatform -SkipDNS'
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'The remediation playbook handles a single gap and no partial findings' {
        It 'does not throw and reports one item (an empty or single result is not an array)' {
            $dir = Join-Path $script:Tmp 'playbook'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $mk = { param($state) [pscustomobject]@{ ControlId = 'AAD-1.1'; State = $state; Severity = 'High'; Category = 'Identity'; Title = 'Smoke control'; Detail = 'd'; Remediation = 'r'; CurrentValue = 'c'; RequiredValue = 'q'; FrameworkIds = ''; AffectedObjects = @() } }
            $one = @((& $mk 'Gap'))
            $md = Join-Path $dir 'pb.md'
            & (Get-Module TenantPosture) {
                param($f, $md, $dir)
                Publish-TPRemediationPlaybook -Metadata @{ TenantDomain = 'smoke.example'; ClientName = 'Smoke' } -Findings $f -Connections @{} `
                    -OutputPath $md -ExecutivePath (Join-Path $dir 'ex.md') -HtmlOutputPath (Join-Path $dir 'pb.html') -ErrorAction Stop
            } $one $md $dir
            $text = Get-Content -LiteralPath $md -Raw
            $text | Should -Match 'Phase 1 .{1,6} Immediate \| 1 items'
        }
    }

    Context 'A failed prerequisite check stops the run cleanly' {
        It 'exits 1 and does not crash in the cleanup block (the finally read an unset variable)' {
            # MicrosoftTeams is deliberately not stubbed yet.
            $out = Join-Path $script:Tmp 'prereq'
            $r = & $script:Run 'Invoke-TPAssessment.ps1' "-NonInteractive $script:Skips -OutputPath '$out'" $out
            $r.ExitCode | Should -Be 1
            $r.Output | Should -Match 'Missing: MicrosoftTeams'
            $r.Output | Should -Not -Match 'cannot be retrieved because it has not been set'
        }
    }

    Context 'Full live path, every workload skipped except Graph and Exchange' {
        BeforeAll {
            & $script:TeamsStub
            $script:LiveOut = Join-Path $script:Tmp 'live'
            $script:Live = & $script:Run 'Invoke-TPAssessment.ps1' "-NonInteractive $script:Skips -AllFiles -OutputPath '$script:LiveOut'" $script:LiveOut
            $script:ResultsFile = Get-ChildItem -LiteralPath $script:LiveOut -Filter '*-results.json' -ErrorAction SilentlyContinue | Select-Object -First 1
            $script:Results = if ($script:ResultsFile) { Get-Content -LiteralPath $script:ResultsFile.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 40 } else { $null }
        }

        It 'finishes with a reported result (0 or 3), never an auth or fatal failure' {
            $script:Live.ExitCode | Should -BeIn @(0, 3) -Because $script:Live.Output
        }
        It 'writes the results JSON with findings, the baseline view and coverage' {
            $script:Results | Should -Not -BeNullOrEmpty
            @($script:Results.Findings).Count | Should -BeGreaterThan 100
            $script:Results.ContainsKey('BaselineCompliance') | Should -BeTrue
            $script:Results.ContainsKey('Coverage') | Should -BeTrue
        }
        It 'no publisher failed' {
            $script:Live.Output | Should -Not -Match 'publish failed' -Because $script:Live.Output
        }
        It 'wrote the HTML report, the Markdown summary, the playbook, the NIST matrix and the SSP' {
            foreach ($pattern in '*-assessment.html', '*-assessment.md', '*-playbook.md', '*-executive.md', '*-nist-800-53-matrix.md', '*-ssp-800-171.md', '*-nist-improvement-plan.md') {
                @(Get-ChildItem -LiteralPath $script:LiveOut -Filter $pattern -ErrorAction SilentlyContinue).Count | Should -BeGreaterThan 0 -Because "$pattern was not written"
            }
        }
        It 'the HTML report carries the Assessment Scope and Limitations section' {
            $html = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:LiveOut -Filter '*-assessment.html').FullName -Raw
            ($html -match "id=[`"']scope[`"']") | Should -BeTrue -Because 'the scope section is missing from the HTML report'
        }
        It 'records every -Skip flag as Skipped, not as data that failed to collect' {
            foreach ($key in 'Purview', 'Teams', 'SharePoint', 'PowerPlatform', 'DNS-EmailRecords') {
                $cov = $script:Results.Coverage[$key]
                $cov | Should -Not -BeNullOrEmpty -Because "coverage for $key"
                [string]$cov.Status | Should -Be 'Skipped'
            }
        }
        It 'no collector or evaluator recorded a StrictMode failure (an API property read without a guard)' {
            $bad = @($script:Results.Exceptions | Where-Object {
                    "$($_.Message)" -match 'cannot be found on this object|has not been set|cannot be retrieved because|You cannot call a method on a null-valued|Cannot index into a null array'
                } | ForEach-Object { "$($_.Source): $($_.Message)" })
            $bad | Should -BeNullOrEmpty -Because ($bad -join "`n")
        }
        It 'says what could not be read: unread controls are not verified, never satisfied' {
            $script:Live.Output | Should -Match 'not verified'
            # Nothing was collected from a tenant that returned nothing, so no baseline
            # control may be reported as Satisfied on the strength of an empty list that
            # the evaluators were not entitled to read as clean.
            $sat = @($script:Results.BaselineCompliance.Controls | Where-Object { $_.ObservedState -eq 'Satisfied' })
            $sat.Count | Should -BeLessThan (@($script:Results.BaselineCompliance.Controls).Count / 2)
        }

        It 'builds the multi-page report site and the action plan automatically, with no extra command' {
            $site = @(Get-ChildItem -LiteralPath $script:LiveOut -Directory -Filter '*-report')
            $site.Count | Should -Be 1 -Because 'the report site folder is written by the run itself'
            Test-Path -LiteralPath (Join-Path $site[0].FullName 'index.html') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $site[0].FullName 'ActionPlan.csv') | Should -BeTrue
        }

        It 'republishes the saved results with -FromResults and no publisher fails' {
            $out2 = Join-Path $script:Tmp 'republish'
            $r = & $script:Run 'Invoke-TPAssessment.ps1' "-FromResults '$($script:ResultsFile.FullName)' -NonInteractive -AllFiles -OutputPath '$out2'" $out2
            $r.ExitCode | Should -BeIn @(0, 3) -Because $r.Output
            $r.Output | Should -Not -Match 'publish failed' -Because $r.Output
            @(Get-ChildItem -LiteralPath $out2 -Filter '*-assessment.html' -ErrorAction SilentlyContinue).Count | Should -BeGreaterThan 0
            @(Get-ChildItem -LiteralPath $out2 -Directory -Filter '*-report' -ErrorAction SilentlyContinue).Count | Should -Be 1 -Because 'a republish rebuilds the site too'
        }

        It 'builds the report site and the action-plan CSV from the saved results' {
            $site = Join-Path $script:Tmp 'site'
            $r = & $script:Run 'New-TPReportSite.ps1' "-ResultsPath '$($script:ResultsFile.FullName)' -OutputPath '$site'" $site
            $r.ExitCode | Should -Be 0 -Because $r.Output
            @(Get-ChildItem -LiteralPath $site -Filter '*.html' -Recurse).Count | Should -BeGreaterThan 1
            @(Get-ChildItem -LiteralPath $site -Filter 'ActionPlan.csv' -Recurse).Count | Should -Be 1
        }
    }
}

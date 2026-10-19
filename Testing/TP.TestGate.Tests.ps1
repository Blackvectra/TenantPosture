#Requires -Version 7.0
#
# TP.TestGate.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# `FailedCount -eq 0` is not "the suite passed". A container that fails
# DISCOVERY runs no tests, so it reports no failures: on 2026-10-15 a merge
# resolution dropped one closing brace in TP.IdentityTruth.Tests.ps1, the local
# check read FailedCount, saw 0, and approved the merge — Pester on main then
# failed at parse before a single test ran. A wrong or empty test path passes the
# same check for the same reason.
#
# These tests drive tools/Invoke-TPTestGate.ps1's two decision functions with
# the shapes that bug produces, and pin that CI goes through the same gate, so
# the local check and the CI check cannot drift apart again.

Describe 'Test gate' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:GatePath = Join-Path $script:RepoRoot 'tools/Invoke-TPTestGate.ps1'

        # Dot-sourced here, not at file scope: top-level code runs during
        # DISCOVERY and its functions are gone by the run phase. -DefinitionsOnly
        # defines the functions and runs nothing, so the gate's own decisions are
        # testable without a nested Pester run.
        . $script:GatePath -DefinitionsOnly

        # A run Pester reports for a clean suite.
        function script:NewRunResult {
            param([hashtable] $Override = @{})

            $fields = @{
                Result                = 'Passed'
                TotalCount            = 12
                PassedCount           = 12
                FailedCount           = 0
                SkippedCount          = 0
                FailedBlocksCount     = 0
                FailedContainersCount = 0
                Containers            = @(
                    [pscustomobject]@{ Name = 'TP.Example.Tests.ps1'; Result = 'Passed'; ErrorRecord = @() }
                )
            }
            foreach ($key in $Override.Keys) { $fields[$key] = $Override[$key] }
            return [pscustomobject] $fields
        }
    }

    Context 'A run that verified nothing is not a pass' {

        It 'accepts a clean run' {
            @(Get-TPPesterRunProblem -Result (NewRunResult)) | Should -BeNullOrEmpty
        }

        It 'rejects a failed test' {
            $problems = @(Get-TPPesterRunProblem -Result (NewRunResult @{
                Result = 'Failed'; FailedCount = 1; PassedCount = 11
            }))
            $problems | Should -Not -BeNullOrEmpty
            ($problems -join ' ') | Should -Match 'FailedCount is 1'
        }

        It 'rejects a failed container while FailedCount is zero — the 2026-10-15 parse failure' {
            # Exactly what a test file that does not parse produces: the
            # container failed, no test ran, so nothing failed.
            $problems = @(Get-TPPesterRunProblem -Result (NewRunResult @{
                Result                = 'Failed'
                TotalCount            = 0
                PassedCount           = 0
                FailedCount           = 0
                FailedContainersCount = 1
                Containers            = @(
                    [pscustomobject]@{
                        Name        = 'TP.IdentityTruth.Tests.ps1'
                        Result      = 'Failed'
                        ErrorRecord = @('The Try statement is missing its Catch or Finally block.')
                    }
                )
            }))
            $problems | Should -Not -BeNullOrEmpty
            $joined = $problems -join ' '
            $joined | Should -Match 'FailedContainersCount is 1'
            $joined | Should -Match 'TP\.IdentityTruth\.Tests\.ps1'
            $joined | Should -Match 'No tests ran'
        }

        It 'rejects a failed block while FailedCount is zero' {
            $problems = @(Get-TPPesterRunProblem -Result (NewRunResult @{
                Result = 'Failed'; FailedBlocksCount = 1
            }))
            ($problems -join ' ') | Should -Match 'FailedBlocksCount is 1'
        }

        It 'rejects a run where no test ran, counts all zero' {
            # A typo'd test path: no files, no tests, no failures.
            $problems = @(Get-TPPesterRunProblem -Result (NewRunResult @{
                TotalCount = 0; PassedCount = 0; Containers = @()
            }))
            ($problems -join ' ') | Should -Match 'No tests ran'
        }

        It 'rejects an overall Result that is not Passed even when every count is zero' {
            $problems = @(Get-TPPesterRunProblem -Result (NewRunResult @{ Result = 'Failed' }))
            ($problems -join ' ') | Should -Match "Result is 'Failed'"
        }

        It 'accepts a container whose tests were all skipped' {
            # Pode is absent on the Ubuntu job and Windows ACL semantics are
            # absent on Linux, so whole contexts legitimately skip. A gate that
            # called that a failure is a gate people route around.
            @(Get-TPPesterRunProblem -Result (NewRunResult @{
                Containers = @(
                    [pscustomobject]@{ Name = 'TP.WebServer.Tests.ps1'; Result = 'Skipped'; ErrorRecord = @() },
                    [pscustomobject]@{ Name = 'TP.Example.Tests.ps1';   Result = 'NotRun';  ErrorRecord = @() }
                )
                SkippedCount = 12
                PassedCount  = 0
            })) | Should -BeNullOrEmpty
        }

        It 'rejects a container error even when the container result reads Passed' {
            $problems = @(Get-TPPesterRunProblem -Result (NewRunResult @{
                Containers = @(
                    [pscustomobject]@{ Name = 'TP.Example.Tests.ps1'; Result = 'Passed'; ErrorRecord = @('BeforeAll threw') }
                )
            }))
            ($problems -join ' ') | Should -Match 'errored'
        }

        It 'rejects no run result at all' {
            @(Get-TPPesterRunProblem -Result $null).Count | Should -BeGreaterThan 0
        }
    }

    Context 'A result shape the installed Pester does not report is never read as zero' {

        It 'rejects an object with no FailedCount' {
            # StrictMode is on: reading a property that is not there throws, and
            # the gate must report that rather than die or treat it as a pass.
            $result = [pscustomobject]@{ Result = 'Passed'; TotalCount = 3 }
            $problems = @(Get-TPPesterRunProblem -Result $result)
            ($problems -join ' ') | Should -Match 'no FailedCount'
        }

        It 'accepts a run that reports no block or container counts but does report containers' {
            $result = [pscustomobject]@{
                Result      = 'Passed'
                TotalCount  = 3
                FailedCount = 0
                Containers  = @([pscustomobject]@{ Name = 'TP.Example.Tests.ps1'; Result = 'Passed' })
            }
            @(Get-TPPesterRunProblem -Result $result) | Should -BeNullOrEmpty
        }

        It 'rejects a run that reports neither container results nor container counts' {
            $result = [pscustomobject]@{ Result = 'Passed'; TotalCount = 3; FailedCount = 0 }
            $problems = @(Get-TPPesterRunProblem -Result $result)
            ($problems -join ' ') | Should -Match 'cannot be ruled out'
        }

        It 'reads a hashtable result as well as an object' {
            @(Get-TPPesterRunProblem -Result @{
                Result = 'Passed'; TotalCount = 1; FailedCount = 0
                Containers = @([pscustomobject]@{ Name = 'x'; Result = 'Passed' })
            }) | Should -BeNullOrEmpty
        }
    }

    Context 'The parse scan runs before Pester' {

        BeforeAll {
            $script:ScanDir = Join-Path $TestDrive 'scan'
            New-Item -ItemType Directory -Path $script:ScanDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $script:ScanDir 'TP.Good.Tests.ps1') -Encoding utf8 `
                -Value "Describe 'ok' { It 'runs' { 1 | Should -Be 1 } }"
            # The 2026-10-15 defect: one closing brace short.
            Set-Content -LiteralPath (Join-Path $script:ScanDir 'TP.Unclosed.Tests.ps1') -Encoding utf8 `
                -Value "Describe 'broken' { It 'never parses' { 1 | Should -Be 1 }"
        }

        It 'names the file and line that does not parse' {
            $found = @(Get-TPUnparsableTestFile -Path $script:ScanDir)
            $found.Count | Should -BeGreaterThan 0
            ($found.File -join ' ') | Should -Match 'TP\.Unclosed\.Tests\.ps1'
            ($found.File -join ' ') | Should -Not -Match 'TP\.Good\.Tests\.ps1'
            @($found | Where-Object { $_.Line -gt 0 }).Count | Should -BeGreaterThan 0
        }

        It 'accepts a directory whose test files all parse' {
            $goodDir = Join-Path $TestDrive 'good'
            New-Item -ItemType Directory -Path $goodDir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $goodDir 'TP.Fine.Tests.ps1') -Encoding utf8 `
                -Value "Describe 'ok' { It 'runs' { 1 | Should -Be 1 } }"
            @(Get-TPUnparsableTestFile -Path $goodDir) | Should -BeNullOrEmpty
        }

        It 'reports a path that is not there instead of scanning nothing' {
            $found = @(Get-TPUnparsableTestFile -Path (Join-Path $TestDrive 'no-such-dir'))
            ($found.Message -join ' ') | Should -Match 'not found'
        }

        It 'reports a directory with no test files' {
            $emptyDir = Join-Path $TestDrive 'empty'
            New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
            $found = @(Get-TPUnparsableTestFile -Path $emptyDir)
            ($found.Message -join ' ') | Should -Match 'No \*\.Tests\.ps1'
        }

        It 'takes a single file as well as a directory' {
            @(Get-TPUnparsableTestFile -Path (Join-Path $script:ScanDir 'TP.Good.Tests.ps1')) | Should -BeNullOrEmpty
            @(Get-TPUnparsableTestFile -Path (Join-Path $script:ScanDir 'TP.Unclosed.Tests.ps1')).Count |
                Should -BeGreaterThan 0
        }

        It 'parses every test file in this repository' {
            # The gate's own verdict on the real tree, so a file that stops
            # parsing fails here as well as in the CI step.
            @(Get-TPUnparsableTestFile -Path @(
                (Join-Path $script:RepoRoot 'Testing'),
                (Join-Path $script:RepoRoot 'Email-IR/Testing')
            )) | Should -BeNullOrEmpty
        }
    }

    Context 'CI and the local check are the same gate' {

        BeforeAll {
            $script:Ci = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/ci.yml') -Raw
        }

        It 'the gate script exists and parses' {
            Test-Path -LiteralPath $script:GatePath | Should -BeTrue
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script:GatePath, [ref] $null, [ref] $errors)
            @($errors).Count | Should -Be 0
        }

        It 'every CI job that runs Pester runs it through the gate' {
            $script:Ci | Should -Match 'Invoke-TPTestGate\.ps1'
            # No job may call Invoke-Pester directly: that is the check that
            # read FailedCount and nothing else.
            $script:Ci | Should -Not -Match '(?m)^\s*Invoke-Pester'
        }

        It 'the contributing checklist points at the gate, not a bare Invoke-Pester' {
            $template = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/PULL_REQUEST_TEMPLATE.md') -Raw
            $template | Should -Match 'Invoke-TPTestGate\.ps1'
        }

        It 'the gate runs the pinned Pester and never re-imports one already loaded' {
            # Pester 6 loads a compiled assembly: a forced second import into
            # the session CI already imported it into leaves Should without its
            # operators, and a version floor would let a local run pass under a
            # Pester CI does not use.
            $gate = Get-Content -LiteralPath $script:GatePath -Raw
            $gate | Should -Match "pinned-modules\.psd1'\)\)\.Pester\.Version"
            $gate | Should -Match 'Import-Module Pester -RequiredVersion \$pinnedPester'
            $gate | Should -Not -Match 'Import-Module Pester[^\r\n]*-Force'
            $gate | Should -Not -Match 'Import-Module Pester[^\r\n]*-MinimumVersion'
        }
    }
}
